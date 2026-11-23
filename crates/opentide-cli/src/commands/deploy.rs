//! `opentide deploy --dry-run` (UC-3.1c, #896): the plan `opentide-compile`
//! makes (`cli/commands/deploy.py`, `cli/services/deploy.py` with
//! `dry_run`), as the envelope, the plan view, the compile failures' frames,
//! the CI job summary and the progress events.
//!
//! A deploy that sends (no `--dry-run`) is `deploy_send`'s (UC-4.6).

use std::path::Path;

use opentide_compile::Owned;
use opentide_compile::dry_run::{self, Request};
use opentide_compile::plan::Scope;
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{OsFs, root};

use super::{COMMAND_FAILED, placement};
use crate::env::Env;
use crate::envelope::{Failure, NextAction, Outcome, USAGE_EXIT_CODE, code};
use crate::json::Json;
use crate::render::diagnostic::{Diagnostic, Severity};
use crate::render::glyphs;
use crate::render::progress::{columns, plural};
use crate::render::text::Text;
use anstyle::{AnsiColor, Style};

/// The command path.
pub const COMMAND: &str = "deploy";

/// `--strategy`'s values, which the command checks itself
/// (`opentide_compile::strategy::parse_strategies`) with its own message and
/// suggestion; the catalogue lists them.
pub const STRATEGIES: [&str; 2] = ["PREVIEW", "RELEASE"];

/// The last line of a dry run in the text modes: the plan above it is all
/// that happened.
pub const DRY_RUN_NOTE: &str = "dry run, nothing sent";

/// `failure.code` of a run that skipped (`not_run`).
const NOT_RUN: &str = "not_run";
/// `failure.code` of a run with findings.
const ISSUES_FOUND: &str = "issues_found";

/// The next step of a run outside any workspace (`NO_WORKSPACE_STEP`).
const NO_WORKSPACE_STEP: (&str, &str) = ("opentide setup", "no workspace here: create one");

/// The command's arguments.
#[derive(Clone, Debug, Default)]
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
    /// `--plan` (removed in 0.17.0, refused by name).
    pub plan: Option<String>,
    /// `--wide`.
    pub wide: bool,
    /// `--keep-deprecated` / `--drop-deprecated`.
    pub keep_deprecated: Option<bool>,
    /// `--skip-promotion`: the push's deploy does not promote, so the dry
    /// run previews no promotion either.
    pub skip_promotion: bool,
}

impl From<&crate::tree::DeployArgs> for Args {
    fn from(args: &crate::tree::DeployArgs) -> Self {
        Self {
            strategies: args.strategy.clone(),
            all: args.all_files,
            uuids: args.uuids.clone(),
            files: args.files.clone(),
            platform: args.platform.as_ref().map(|platform| platform.0.clone()),
            plan: args.plan.clone(),
            skip_promotion: args.skip_promotion,
            wide: args.wide,
            keep_deprecated: if args.keep_deprecated {
                Some(true)
            } else if args.drop_deprecated {
                Some(false)
            } else {
                None
            },
        }
    }
}

/// What the run knows about where it is.
pub struct Context<'a> {
    /// `--repo`, as typed.
    pub repo: Option<&'a str>,
    /// The environment.
    pub env: &'a Env,
    /// The working directory.
    pub cwd: &'a Path,
    /// `--debug` or `OPENTIDE_DEBUG`: the push's deploy promotes every rule
    /// file, and so does the preview.
    pub debug: bool,
}

/// A dry run's result, as every mode prints it.
#[derive(Clone, Debug)]
pub struct DryRun {
    /// The envelope's parts; `data` holds the command's keys in order.
    pub outcome: Outcome,
    /// `warning:` lines, and the document's `warnings`.
    pub warnings: Vec<String>,
    /// The outcome line, when it is not the message.
    pub outcome_line: Option<String>,
    /// Whether the outcome line is a plan's tally.
    pub plan_kind: bool,
    /// The service's result as the CI job summary reads it: the command's
    /// keys with `message`, `status` and `warnings`.
    pub result: Json,
    /// The rules that would fail to deploy, as code frames.
    pub diagnostics: Vec<Diagnostic>,
    /// The platforms compiled, in order: one progress event each.
    pub compiled: Vec<String>,
    /// Whether the run was refused before it started: no plan, no summary,
    /// no closing note.
    pub refused: bool,
}

impl DryRun {
    /// `detail` (a `note:`) from the command's keys.
    pub fn detail(&self) -> Option<String> {
        self.data_str("detail")
    }

    /// `advice` (a `help:`) from the command's keys.
    pub fn advice(&self) -> Option<String> {
        self.data_str("advice")
    }

    fn data_str(&self, key: &str) -> Option<String> {
        self.outcome
            .data
            .iter()
            .find(|(name, _)| name == key)
            .and_then(|(_, value)| match value {
                Json::Str(text) if !text.is_empty() => Some(text.clone()),
                _ => None,
            })
    }

    /// The JSON document, `duration_ms` as given: the command's keys, then
    /// `ok`, `status`, `message`, `warnings` (the run's, with the command's
    /// own merged in by `put_warnings`), then `error` when the run
    /// exits non-zero and its keys hold none, then the envelope's keys.
    pub fn document(&self, duration_ms: i64) -> Json {
        let had_error = self.outcome.data.iter().any(|(key, _)| key == "error");
        let Json::Object(mut members) = self.outcome.document(duration_ms) else {
            return Json::Null;
        };
        let error = if had_error {
            None
        } else {
            members.shift_remove("error")
        };
        crate::envelope::put_warnings(&mut members, &self.warnings);
        if let Some(error) = error {
            let at = members
                .get_index_of(if self.warnings.is_empty() {
                    "message"
                } else {
                    "warnings"
                })
                .map_or(members.len(), |at| at + 1);
            members.shift_insert(at, "error".into(), error);
        }
        Json::Object(members)
    }

    /// The plan view (`render_plan`): a header, then the rows of each
    /// platform and tenant, each line with the indent it continues at when
    /// a terminal wraps it (`None`: never wrapped). Empty when the run
    /// planned nothing.
    pub fn plan_lines(&self) -> Vec<(Text, Option<usize>)> {
        plan_view(&self.result, &self.outcome.summary)
    }
}

/// The usage refusal of a run, dry or not, before it starts: the removed
/// `--plan`, or `--all` with a selection.
pub fn refusal(args: &Args) -> Option<DryRun> {
    if let Some(plan) = &args.plan {
        return Some(refused(
            opentide_compile::strategy::removed_plan_message(Some(plan), true),
            code::USAGE_INVALID_VALUE,
            "--plan",
        ));
    }
    if args.all && (!args.uuids.is_empty() || !args.files.is_empty()) {
        return Some(refused(
            "--all reads every rule file; --uuid and --file select rules instead. Pass one or \
             the other"
                .to_owned(),
            code::USAGE_ERROR,
            if args.uuids.is_empty() {
                "--file"
            } else {
                "--uuid"
            },
        ));
    }
    None
}

/// Runs `deploy --dry-run`.
pub fn run(args: &Args, cx: &Context<'_>) -> DryRun {
    if let Some(refused) = refusal(args) {
        return refused;
    }
    let (_, options) = placement(cx.repo, cx.env, cx.cwd);
    let workspace = match super::open_for(COMMAND, options.clone()) {
        Ok(workspace) => workspace,
        Err(refused) => {
            // A TOML file that does not parse keeps `config_parse`, its place
            // and its diagnostic.
            let mut dry = failed(refused.outcome.message.clone());
            dry.outcome = refused.outcome;
            return dry;
        }
    };
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    // A RELEASE push promotes before it deploys: plan the promoted rules,
    // as the push's deploy will (#1653, smoke E13).
    let preview = match preview(args, cx, &workspace, &owned, options) {
        Ok(preview) => preview,
        Err(message) => return failed(message),
    };
    let (workspace, promoted, stops) = match preview {
        Some(super::promotion_preview::Preview::Promoted {
            workspace: promoted,
            files,
            uuids,
            target,
        }) => {
            crate::app::release(workspace);
            (*promoted, Some((files, uuids, target)), None)
        }
        Some(super::promotion_preview::Preview::Stops(message)) => (workspace, None, Some(message)),
        Some(super::promotion_preview::Preview::Nothing) | None => (workspace, None, None),
    };
    let request = Request {
        strategies: args.strategies.clone(),
        all: args.all,
        uuids: args.uuids.clone(),
        files: args.files.clone(),
        platform: args.platform.clone(),
        wide: args.wide,
        keep_deprecated: args.keep_deprecated,
        removed_plan: cx
            .env
            .get(opentide_compile::strategy::REMOVED_PLAN_ENV)
            .map(str::to_owned),
        cwd: cx.cwd.to_path_buf(),
        plugins: crate::plugins::plugin_ids(),
    };
    let env = |name: &str| cx.env.get(name).map(str::to_owned);
    let root_dir = workspace.root().to_path_buf();
    // The push's deploy also sends what a whole-folder promotion rewrote.
    let promoted_files: Vec<std::path::PathBuf> = promoted
        .as_ref()
        .map(|(files, _, _)| files.clone())
        .unwrap_or_default();
    let changed =
        |rules: &Path, folder: &str| -> Result<(Scope, Option<String>), dry_run::ScopeError> {
            let (mut scope, warning) =
                dry_run::git_scope_also(&root_dir, cx.cwd, &env, rules, folder, &promoted_files)?;
            for file in &promoted_files {
                if !scope.files.contains(file) {
                    scope.files.push(file.clone());
                }
            }
            Ok((scope, warning))
        };
    let is_set = |name: &str| cx.env.get(name).is_some();
    let outcome = dry_run::run(&workspace, &owned, &request, &changed, &is_set);
    let at_root = root::is_workspace_root(&OsFs, workspace.root());
    let mut result = from_outcome(outcome, at_root);
    if let Some(message) = stops {
        result.warnings.insert(
            0,
            format!("the push's deploy would stop at its status promotion: {message}"),
        );
    }
    for warning in promotion_warnings(args, cx, &owned).into_iter().rev() {
        result.warnings.insert(0, warning);
    }
    if let Some((_, uuids, target)) = promoted {
        // Only the promoted rules a tenant receives keep their promotion:
        // the deploy puts the others back.
        let planned = planned_uuids(&result.result);
        let count = uuids.iter().filter(|uuid| planned.contains(*uuid)).count();
        if count > 0 {
            result.warnings.insert(
                0,
                format!(
                    "the push's deploy promotes {} to {target} first (status promotion): the \
                     plan shows {} promoted, and nothing is written",
                    plural(count, "rule", None),
                    if count == 1 { "it" } else { "them" }
                ),
            );
        }
    }
    // The index is large on a heavy workspace (see `app::release`).
    crate::app::release(workspace);
    result
}

/// The canonical UUIDs of the rules a dry run's `changes` send to a tenant.
fn planned_uuids(result: &Json) -> Vec<String> {
    match result.get("changes") {
        Some(Json::Array(changes)) => changes
            .iter()
            .filter(|change| change.get("tenant").is_some_and(|tenant| !tenant.is_null()))
            .filter_map(|change| change.get("uuid").and_then(Json::as_str))
            .map(opentide_compile::rule::canonical_uuid)
            .collect(),
        _ => Vec::new(),
    }
}

/// What the push's deploy does at its status promotion, when the run is one
/// that promotes.
fn preview(
    args: &Args,
    cx: &Context<'_>,
    workspace: &opentide_workspace::Workspace,
    owned: &Owned,
    options: opentide_workspace::RootOptions,
) -> Result<Option<super::promotion_preview::Preview>, String> {
    let reads_changes = !args.all && args.uuids.is_empty() && args.files.is_empty();
    if args.skip_promotion || !reads_changes {
        return Ok(None);
    }
    let Ok(runs) = opentide_compile::strategy::parse_strategies(
        &args.strategies,
        &owned.statuses,
        "--strategy",
    ) else {
        return Ok(None);
    };
    if !super::promotion_preview::applies(&runs, reads_changes, cx.env) {
        return Ok(None);
    }
    let (rules_dir, folder) = dry_run::rules_folder(workspace);
    let env = |name: &str| cx.env.get(name).map(str::to_owned);
    // The dry run reports a diff it cannot read itself.
    let Ok((scope, _)) = dry_run::git_scope(workspace.root(), cx.cwd, &env, &rules_dir, &folder)
    else {
        return Ok(None);
    };
    let local = if cx.debug {
        opentide_compile::plan::local_scope(workspace.fs().as_ref(), &rules_dir, &folder).files
    } else {
        Vec::new()
    };
    super::promotion_preview::promoted_workspace(owned, options, &scope.files, &local, cx.debug)
        .map(Some)
}

/// The warnings of a push that could promote: a branch the CI environment
/// does not say, and a stale `OPENTIDE_DEFAULT_BRANCH`.
fn promotion_warnings(args: &Args, cx: &Context, owned: &Owned) -> Vec<String> {
    let reads_changes = !args.all && args.uuids.is_empty() && args.files.is_empty();
    if args.skip_promotion || !reads_changes {
        return Vec::new();
    }
    let Ok(runs) = opentide_compile::strategy::parse_strategies(
        &args.strategies,
        &owned.statuses,
        "--strategy",
    ) else {
        return Vec::new();
    };
    let enabled =
        opentide_compile::promotion::Settings::new(&owned.config, &owned.statuses).enabled;
    super::promotion_preview::warnings(&runs, reads_changes, cx.env, enabled)
}

/// A run refused before it started: a usage error, exit 2.
fn refused(message: String, failure_code: &str, argument: &str) -> DryRun {
    let mut failure = Failure::new(failure_code, message);
    failure.argument = Some(argument.to_owned());
    let outcome = Outcome::failed(COMMAND, USAGE_EXIT_CODE, failure);
    DryRun {
        result: Json::Null,
        outcome,
        warnings: Vec::new(),
        outcome_line: None,
        plan_kind: false,
        diagnostics: Vec::new(),
        compiled: Vec::new(),
        refused: true,
    }
}

/// A run that stopped on an error of its own (the workspace did not open).
fn failed(message: String) -> DryRun {
    let outcome = Outcome::failed(COMMAND, 1, Failure::new(COMMAND_FAILED, message.clone()));
    DryRun {
        result: Json::object([
            ("status", Json::str("failed")),
            ("message", Json::Str(message)),
        ]),
        outcome,
        warnings: Vec::new(),
        outcome_line: None,
        plan_kind: false,
        diagnostics: Vec::new(),
        compiled: Vec::new(),
        refused: false,
    }
}

/// `opentide-compile`'s JSON as this crate's.
pub fn convert(value: &opentide_compile::Json) -> Json {
    use opentide_compile::Json as From;
    match value {
        From::Null => Json::Null,
        From::Bool(flag) => Json::Bool(*flag),
        From::Int(integer) => Json::Int(*integer),
        From::UInt(integer) => Json::UInt(*integer),
        From::Float(float) => Json::Float(*float),
        From::Str(text) => Json::Str(text.clone()),
        From::Array(items) => Json::Array(items.iter().map(convert).collect()),
        From::Object(members) => Json::Object(
            members
                .iter()
                .map(|(key, value)| (key.clone(), convert(value)))
                .collect(),
        ),
    }
}

/// The envelope's parts of a service result (`CommandResult.from_payload`):
/// `message`, `status` and `warnings` leave the command's keys, the usage
/// failure or the status names `failure.code`.
fn from_outcome(outcome: dry_run::Outcome, at_root: bool) -> DryRun {
    let result = convert(&opentide_compile::Json::Object(outcome.payload.clone()));
    let mut data: Vec<(String, Json)> = Vec::new();
    let mut message = "Deployment completed".to_owned();
    let mut status = "completed".to_owned();
    let mut warnings: Vec<String> = Vec::new();
    if let Json::Object(members) = &result {
        for (key, value) in members {
            match (key.as_str(), value) {
                ("message", Json::Str(text)) => text.clone_into(&mut message),
                ("status", Json::Str(text)) => text.clone_into(&mut status),
                ("warnings", Json::Array(items)) => {
                    warnings = items
                        .iter()
                        .map(|item| match item {
                            Json::Str(text) => text.clone(),
                            other => crate::json::document_text(other, false)
                                .trim_end()
                                .to_owned(),
                        })
                        .collect();
                }
                _ => data.push((key.clone(), value.clone())),
            }
        }
    }
    let exit_code = outcome.exit_code;
    let ok = status != "failed";
    let failure = if let Some(usage) = &outcome.usage {
        let mut failure = Failure::new(usage.code, message.clone());
        failure.argument = usage.argument.map(str::to_owned);
        failure.suggestion.clone_from(&usage.suggestion);
        Some(failure)
    } else if !ok || exit_code != 0 {
        let failure_code = match status.as_str() {
            "issues" => ISSUES_FOUND,
            "skipped" => NOT_RUN,
            _ => COMMAND_FAILED,
        };
        let error = data
            .iter()
            .find(|(key, _)| key == "error")
            .and_then(|(_, value)| match value {
                Json::Str(text) if !text.is_empty() => Some(text.clone()),
                _ => None,
            })
            .unwrap_or_else(|| message.clone());
        Some(Failure::new(failure_code, error))
    } else {
        None
    };
    let mut next_actions = Vec::new();
    if status == "skipped" && !at_root {
        next_actions.push(NextAction::new(NO_WORKSPACE_STEP.0, NO_WORKSPACE_STEP.1));
    }
    let summary = match outcome.summary.as_ref().map(convert) {
        Some(Json::Object(members)) => members.into_iter().collect(),
        _ => Vec::new(),
    };
    let diagnostics = result
        .get("diagnostics")
        .map(|items| match items {
            Json::Array(items) => items.iter().map(plan_diagnostic).collect(),
            _ => Vec::new(),
        })
        .unwrap_or_default();
    let compiled = match result.get("payloads") {
        Some(Json::Object(members)) => members.iter().map(|(key, _)| key.clone()).collect(),
        _ => Vec::new(),
    };
    DryRun {
        outcome: Outcome {
            command: COMMAND.to_owned(),
            status,
            message,
            data,
            exit_code,
            summary,
            next_actions,
            failure,
        },
        warnings,
        outcome_line: outcome.outcome_line,
        plan_kind: outcome.outcome_kind == Some("plan"),
        result,
        diagnostics,
        compiled,
        refused: false,
    }
}

/// Markdown code spans (`` `response` ``) quoted as every other frame
/// quotes a name (`'response'`).
fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('`') {
        let after = &rest[start + 1..];
        match after.find('`') {
            Some(end) if end > 0 => {
                out.push_str(&rest[..start]);
                out.push('\'');
                out.push_str(&after[..end]);
                out.push('\'');
                rest = &after[end + 1..];
            }
            _ => {
                out.push_str(&rest[..=start]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// One rule a dry run could not compile, as a code frame (`plan_diagnostic`):
/// the frame's location names the rule's file, so a rule with no file is
/// named in a note instead.
fn plan_diagnostic(item: &Json) -> Diagnostic {
    let text = |key: &str| match item.get(key) {
        Some(Json::Str(text)) if !text.is_empty() => Some(text.clone()),
        _ => None,
    };
    let severity = if text("severity").as_deref() == Some("warning") {
        Severity::Warning
    } else {
        Severity::Error
    };
    let mut diagnostic = Diagnostic::new(
        &text("code").unwrap_or_else(|| "compile_failed".to_owned()),
        severity,
        &quoted(&text("message").unwrap_or_default()),
    );
    let source = text("file_path");
    let path = text("path");
    if source.is_none() && path.is_none() {
        diagnostic.notes = vec![(
            "rule".to_owned(),
            text("name").or_else(|| text("uuid")).unwrap_or_default(),
        )];
    }
    diagnostic.path = path;
    diagnostic.file_path = source.map(Into::into);
    diagnostic.help = text("help").map(|help| quoted(&help));
    diagnostic.object_uuid = text("uuid");
    diagnostic
}

/// The UUID's tail after `…` (`short_uuid`).
pub fn short_uuid(uuid: &str) -> String {
    let count = uuid.chars().count();
    if count <= 12 {
        return uuid.to_owned();
    }
    let tail: String = uuid.chars().skip(count - 12).collect();
    format!("…{tail}")
}

/// A row's glyph, label and style by action (`_ROWS`); an unknown action is
/// a create or update.
fn row_style(action: &str) -> (&'static str, &'static str, Style) {
    match action {
        "create" => ("+", "create", AnsiColor::Green.on_default().bold()),
        "update" => ("~", "update", AnsiColor::Yellow.on_default().bold()),
        "disable" => (
            glyphs::DISABLE,
            "disable",
            AnsiColor::Magenta.on_default().bold(),
        ),
        "delete" => ("×", "delete", AnsiColor::Red.on_default().bold()),
        _ => (
            "+",
            "create or update",
            AnsiColor::Green.on_default().bold(),
        ),
    }
}

fn json_text(value: Option<&Json>) -> String {
    match value {
        Some(Json::Str(text)) => text.clone(),
        Some(Json::Null) | None => String::new(),
        Some(other) => crate::json::document_text(other, false)
            .trim_end()
            .to_owned(),
    }
}

/// The plan grouped by platform, then tenant (`plan_view`).
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
fn plan_view(result: &Json, summary: &[(String, Json)]) -> Vec<(Text, Option<usize>)> {
    let Some(Json::Array(changes)) = result.get("changes") else {
        return Vec::new();
    };
    if changes.is_empty() {
        return Vec::new();
    }
    let count = |key: &str| {
        summary
            .iter()
            .find(|(name, _)| name == key)
            .and_then(|(_, value)| match value {
                Json::Int(number) => usize::try_from(*number).ok(),
                _ => None,
            })
    };
    let scope = match (count("platforms"), count("tenants")) {
        (Some(platforms), Some(tenants)) => Some(format!(
            "{}, {}",
            plural(platforms, "platform", None),
            plural(tenants, "tenant", None)
        )),
        _ => None,
    };
    let separator = format!(" {} ", glyphs::SEPARATOR);
    let (bold, dim) = (Style::new().bold(), Style::new().dimmed());
    // The header is bold throughout, its labels bold and dim.
    let bold_dim = bold.dimmed();
    let mut header = Text::styled("Deploy plan", &bold);
    let strategies: Vec<String> = match result.get("strategies") {
        Some(Json::Array(items)) => items.iter().map(|item| json_text(Some(item))).collect(),
        _ => Vec::new(),
    };
    if !strategies.is_empty() {
        header.append(&format!("{separator}strategy "), &bold_dim);
        header.append(&strategies.join(" "), &bold);
    }
    if let Some(scope) = scope {
        header.append(&format!("{separator}{scope}"), &bold_dim);
    }
    header.append(&format!("{separator}dry run, nothing is sent"), &bold_dim);
    let mut lines: Vec<(Text, Option<usize>)> = vec![(header, Some(4))];
    let mut platforms: Vec<(String, Vec<&Json>)> = Vec::new();
    for change in changes {
        let platform = json_text(change.get("platform"));
        match platforms.iter_mut().find(|(name, _)| *name == platform) {
            Some((_, rows)) => rows.push(change),
            None => platforms.push((platform, vec![change])),
        }
    }
    let tenants = result.get("tenants");
    for (platform, rows) in &platforms {
        let mut names: Vec<String> = rows
            .iter()
            .filter_map(|row| match row.get("tenant") {
                Some(Json::Str(tenant)) if !tenant.is_empty() => Some(tenant.clone()),
                _ => None,
            })
            .collect();
        names.sort();
        names.dedup();
        let configured = match tenants.and_then(|tenants| tenants.get(platform)) {
            Some(Json::Object(members)) if !members.is_empty() => members.len(),
            _ => names.len(),
        };
        lines.push((Text::default(), Some(4)));
        let mut title = Text::styled(platform, &bold);
        title.append(
            &format!("{separator}{}", plural(configured, "tenant", None)),
            &dim,
        );
        lines.push((title, Some(4)));
        let mut groups: Vec<(Option<String>, Vec<&Json>)> = Vec::new();
        for row in rows {
            let tenant = match row.get("tenant") {
                Some(Json::Null) | None => None,
                Some(other) => Some(json_text(Some(other))),
            };
            match groups.iter_mut().find(|(name, _)| *name == tenant) {
                Some((_, members)) => members.push(row),
                None => groups.push((tenant, vec![row])),
            }
        }
        for (tenant, members) in &groups {
            if let Some(tenant) = tenant {
                let mut line = Text::plain("  ");
                line.append(tenant, &bold);
                lines.push((line, Some(6)));
            }
            let cells: Vec<Vec<Text>> = members
                .iter()
                .map(|row| {
                    let (mut glyph, mut label, mut style) =
                        row_style(&json_text(row.get("action")));
                    if row.get("fails") == Some(&Json::Bool(true)) {
                        // Its frame prints below; the row must not promise a create.
                        (glyph, label, style) = (
                            glyphs::FAILED,
                            "would fail",
                            AnsiColor::Red.on_default().bold(),
                        );
                    }
                    let uuid = json_text(row.get("uuid"));
                    let name = match row.get("name") {
                        Some(Json::Str(name)) if !name.is_empty() => name.clone(),
                        _ => uuid.clone(),
                    };
                    let status = match row.get("status") {
                        Some(Json::Str(status)) if !status.is_empty() => {
                            format!("status {status}")
                        }
                        _ => String::new(),
                    };
                    vec![
                        Text::styled(&format!("{glyph} {label}"), &style),
                        Text::styled(&name, &bold),
                        Text::styled(&short_uuid(&uuid), &dim),
                        Text::styled(&status, &dim),
                    ]
                })
                .collect();
            let indent = if tenant.is_some() { 4 } else { 2 };
            for line in columns(&cells, 2, indent, &[]) {
                lines.push((line, None));
            }
        }
    }
    lines.push((Text::default(), Some(4)));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_spans_are_quoted_as_frames_quote_names() {
        assert_eq!(quoted("set `response` and `x`"), "set 'response' and 'x'");
        assert_eq!(quoted("a lone ` stays"), "a lone ` stays");
        assert_eq!(quoted("``"), "``");
    }

    #[test]
    fn a_uuid_shows_its_last_twelve_characters() {
        assert_eq!(
            short_uuid("00000000-0000-4000-8003-000000000001"),
            "…000000000001"
        );
        assert_eq!(short_uuid("short"), "short");
        assert_eq!(short_uuid("123456789012"), "123456789012");
    }

    #[test]
    fn a_failure_without_a_file_names_its_rule_in_a_note() {
        let item = Json::object([
            ("code", Json::str("compile_invalid_rule")),
            ("severity", Json::str("error")),
            ("message", Json::str("bad `query`")),
            ("help", Json::str("fix `it`")),
            ("path", Json::Null),
            ("file_path", Json::Null),
            ("uuid", Json::str("u")),
            ("name", Json::str("Rule")),
        ]);
        let diagnostic = plan_diagnostic(&item);
        assert_eq!(diagnostic.code, "compile_invalid_rule");
        assert_eq!(diagnostic.message, "bad 'query'");
        assert_eq!(diagnostic.help.as_deref(), Some("fix 'it'"));
        assert_eq!(diagnostic.notes, [("rule".to_owned(), "Rule".to_owned())]);
        assert_eq!(diagnostic.object_uuid.as_deref(), Some("u"));
        let mut placed = item.clone();
        if let Json::Object(members) = &mut placed {
            for (key, value) in members.iter_mut() {
                if key == "path" {
                    *value = Json::str("objects/rules/r.yaml");
                }
            }
        }
        let diagnostic = plan_diagnostic(&placed);
        assert!(diagnostic.notes.is_empty());
        assert_eq!(diagnostic.path.as_deref(), Some("objects/rules/r.yaml"));
    }

    #[test]
    fn every_action_has_its_glyph_and_label() {
        assert_eq!(row_style("create").1, "create");
        assert_eq!(
            row_style("update"),
            ("~", "update", AnsiColor::Yellow.on_default().bold())
        );
        assert_eq!(row_style("disable").1, "disable");
        assert_eq!(
            row_style("delete"),
            ("×", "delete", AnsiColor::Red.on_default().bold())
        );
        assert_eq!(
            row_style("upsert"),
            (
                "+",
                "create or update",
                AnsiColor::Green.on_default().bold()
            )
        );
    }

    #[test]
    fn the_strategies_are_the_deployable_ones() {
        let names: Vec<&str> = opentide_compile::strategy::DEPLOYABLE
            .iter()
            .map(|strategy| strategy.name())
            .collect();
        assert_eq!(names, STRATEGIES);
    }
}

#[cfg(test)]
mod from_cli_tests {
    use clap::Parser as _;

    use super::Args;
    use crate::tree::{Cli, RootCommand};

    fn parse(words: &[&str]) -> Args {
        let words = std::iter::once("opentide").chain(words.iter().copied());
        match Cli::try_parse_from(words).map(|cli| cli.command) {
            Ok(Some(RootCommand::Deploy(deploy))) => Args::from(&deploy),
            other => panic!("not a deploy command: {other:?}"),
        }
    }

    #[test]
    fn the_options_are_read_as_typed() {
        let args = parse(&[
            "deploy",
            "--platform",
            "splunk",
            "--strategy",
            "PREVIEW",
            "--strategy",
            "RELEASE",
            "--all",
            "--uuid",
            "u",
            "--file",
            "f.yml",
            "--wide",
        ]);
        assert_eq!(args.platform.as_deref(), Some("splunk"));
        assert_eq!(args.strategies, ["PREVIEW", "RELEASE"]);
        assert!(args.all && args.wide);
        assert_eq!(args.uuids, ["u"]);
        assert_eq!(args.files, ["f.yml"]);
    }

    #[test]
    fn keep_and_drop_deprecated_are_a_tri_state_the_last_one_typed_wins() {
        assert_eq!(parse(&["deploy"]).keep_deprecated, None);
        assert_eq!(
            parse(&["deploy", "--keep-deprecated"]).keep_deprecated,
            Some(true)
        );
        assert_eq!(
            parse(&["deploy", "--drop-deprecated"]).keep_deprecated,
            Some(false)
        );
        assert_eq!(
            parse(&["deploy", "--keep-deprecated", "--drop-deprecated"]).keep_deprecated,
            Some(false)
        );
        assert_eq!(
            parse(&["deploy", "--drop-deprecated", "--keep-deprecated"]).keep_deprecated,
            Some(true)
        );
    }
}
