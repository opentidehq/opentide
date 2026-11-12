//! `opentide share` and its `push`, `preview`, `status`, `retract` and
//! `targets` (UC-4.4b, #834; `cli/services/share.py` and `sharing/`): one
//! MISP Event per Tide object, over MISP's REST API
//! (`opentide_connectors::misp`).
//!
//! The run checks its options, loads `sharing.toml` ([`config`]), picks the
//! destinations, reads the catalogue ([`document`]) and runs the engine
//! ([`engine`]); the result is the oracle's payload: `preflight` codes for a
//! run stopped before any object, records per object and destination, and
//! the exit status sharing 1.0 defines (0, 1, 2 for authentication or
//! connectivity failures, 3 for a partial run). A secret never reaches the
//! output: every string is redacted with the blocks' keys.

pub mod config;
pub mod document;
pub mod engine;
pub mod event;
pub mod ledger;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use opentide_connectors::Environment;
use opentide_connectors::misp::{Misp, MispCallError, MispClient};
use opentide_workspace::Workspace;

use self::config::{Block, Sharing};
use self::engine::{Filters, Record, ShareRun};
use super::{Block as BodyBlock, Report, USAGE_INVALID_CHOICE, USAGE_INVALID_VALUE, placement};
use crate::env::Env;
use crate::envelope::{Failure, USAGE_EXIT_CODE};
use crate::json::Json;
use crate::render::glyphs;
use crate::render::outcome::OutcomeKind;
use crate::render::progress::{columns, plural};
use crate::render::text::{Style, Text};

/// The share subcommand a run is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `share push` (and `share`).
    Push,
    /// `share preview`.
    Preview,
    /// `share status`.
    Status,
    /// `share retract`.
    Retract,
    /// `share targets`.
    Targets,
}

/// A share run's options.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the command line's flags, one field each"
)]
#[derive(Clone, Debug)]
pub struct Args {
    /// The subcommand.
    pub mode: Mode,
    /// `--target`.
    pub targets: Vec<String>,
    /// `--uuid`.
    pub uuids: Vec<String>,
    /// `--type`.
    pub types: Vec<String>,
    /// `--file`.
    pub files: Vec<String>,
    /// `--dry-run`.
    pub dry_run: bool,
    /// `--publish` / `--no-publish`.
    pub publish: Option<bool>,
    /// `--workers`.
    pub workers: i64,
    /// `--delete`.
    pub delete: bool,
    /// `--yes`.
    pub yes: bool,
    /// `--changed`.
    pub changed: bool,
    /// `--since`.
    pub since: Option<String>,
}

/// Where a share runs.
pub struct Context<'a> {
    /// The command path (`share push`).
    pub command: &'a str,
    /// `--repo`.
    pub repo: Option<&'a str>,
    /// The environment.
    pub env: &'a Env,
    /// The working directory.
    pub cwd: &'a Path,
    /// `--proxy`.
    pub proxy: Option<&'a str>,
    /// opentide's version.
    pub version: &'a str,
}

/// The object families sharing knows (`OBJECT_FAMILIES`).
pub const OBJECT_FAMILIES: [&str; 3] = ["threat", "objective", "rule"];
/// The TLP ceiling's order (`TLP_ORDER`).
pub const TLP_ORDER: [&str; 5] = ["clear", "green", "amber", "amber+strict", "red"];
/// What replaces a secret (`REDACTION_MARKER`).
pub const REDACTION_MARKER: &str = "[REDACTED]";

const NO_ENABLED_TARGET: &str = "No enabled sharing target";
const NO_TARGET: &str = "No sharing target is configured";
const ADD_TARGET: &str =
    "add a [[misp]] block to .opentide/configurations/sharing.toml (see docs/cli/share.md)";

/// A preflight's message (`_PREFLIGHT`).
fn preflight_message(code: &str) -> &str {
    match code {
        "scope_no_match" => "No sharing target matched the request",
        "api_key_unset" => "An enabled sharing target has no API key",
        "retract_unconfirmed" => "Pass --yes to delete the remote event",
        "organisation_uuid_mismatch" => "The configured organisation does not match the API key",
        "sharing_config" => "sharing.toml failed validation",
        "changed_outside_ci" => {
            "opentide share push --changed runs only in GitHub Actions, GitLab CI, or Azure \
             Pipelines"
        }
        "changed_on_pull_request" => "opentide share push --changed does not run on a pull request",
        "changed_diff" => "Could not calculate the changed objects",
        other => other,
    }
}

/// The payload a run builds (`run_share`'s dict): the message, status and
/// exit code, the command's own keys in order, and the parts the envelope
/// takes from it (`_failure_code`, `_summary`, `_outcome_kind`, ...).
#[derive(Clone, Debug, Default)]
struct Payload {
    message: String,
    status: String,
    exit_code: i32,
    warnings: Vec<String>,
    data: Vec<(String, Json)>,
    failure_code: Option<String>,
    failure_argument: Option<String>,
    failure_suggestion: Option<String>,
    summary: Vec<(String, Json)>,
    plan: bool,
    outcome: Option<String>,
    /// The rows the text modes print.
    body: Vec<BodyBlock>,
    /// The run needs what this engine does not do; the message says what.
    unported: Option<String>,
}

impl Payload {
    fn result(message: &str, exit_code: i32, status: &str, warnings: Vec<String>) -> Self {
        Self {
            message: message.to_owned(),
            status: status.to_owned(),
            exit_code,
            warnings,
            ..Self::default()
        }
    }

    fn put(&mut self, key: &str, value: Json) {
        match self.data.iter_mut().find(|(name, _)| name == key) {
            Some((_, existing)) => *existing = value,
            None => self.data.push((key.to_owned(), value)),
        }
    }

    /// `_failed`: a usage error the run found itself.
    fn usage(message: &str, code: &str, argument: &str) -> Self {
        let mut payload = Self::result(message, USAGE_EXIT_CODE, "failed", Vec::new());
        payload.put("error", Json::str(message));
        payload.failure_code = Some(code.to_owned());
        payload.failure_argument = Some(argument.to_owned());
        payload
    }

    /// `_preflight`: a run stopped before any object.
    fn preflight(code: &str, sharing: &Sharing, records: &[Record], message: Option<&str>) -> Self {
        let mut payload = Self::result(
            message.unwrap_or_else(|| preflight_message(code)),
            1,
            "failed",
            sharing.warnings(),
        );
        payload.put("preflight", Json::str(code));
        payload.put("records", records_json(records));
        payload.failure_code = Some(code.to_owned());
        payload
    }

    /// `_quiet`: nothing to do, and that is fine.
    fn quiet(message: &str, sharing: &Sharing) -> Self {
        let mut payload = Self::result(message, 0, "completed", sharing.warnings());
        payload.put("records", Json::Array(Vec::new()));
        payload
    }

    fn with_warnings(mut self, extra: &[String]) -> Self {
        self.warnings.extend(extra.iter().cloned());
        self
    }

    /// Every string with each secret replaced (`_redact`).
    fn redacted(mut self, secrets: &[String]) -> Self {
        if secrets.is_empty() {
            return self;
        }
        let text = |value: &mut String| {
            for secret in secrets {
                if value.contains(secret.as_str()) {
                    *value = value.replace(secret.as_str(), REDACTION_MARKER);
                }
            }
        };
        text(&mut self.message);
        self.warnings.iter_mut().for_each(text);
        for (_, value) in &mut self.data {
            redact_json(value, secrets);
        }
        if let Some(outcome) = &mut self.outcome {
            text(outcome);
        }
        self
    }

    fn report(self, command: &str) -> Report {
        if let Some(message) = self.unported {
            return Report::failed(
                command,
                1,
                Failure::new(crate::envelope::code::ENGINE_NOT_PORTED, message),
            );
        }
        let mut report = Report::completed(command, self.data);
        report.outcome.message = self.message;
        report.outcome.status = self.status;
        report.outcome.exit_code = self.exit_code;
        report.outcome.summary = self.summary;
        report.warnings = self.warnings;
        report.body = self.body;
        if self.exit_code != 0 {
            let code = self.failure_code.unwrap_or_else(|| {
                if self.exit_code == USAGE_EXIT_CODE {
                    USAGE_INVALID_VALUE.to_owned()
                } else {
                    super::COMMAND_FAILED.to_owned()
                }
            });
            let mut failure = Failure::new(&code, report.outcome.message.clone());
            failure.argument = self.failure_argument;
            failure.suggestion = self.failure_suggestion;
            report.outcome.failure = Some(failure);
        }
        if self.plan {
            report.outcome_kind = Some(OutcomeKind::Plan);
        }
        report.outcome_line = self.outcome;
        report
    }
}

fn redact_json(value: &mut Json, secrets: &[String]) {
    match value {
        Json::Str(text) => {
            for secret in secrets {
                if text.contains(secret.as_str()) {
                    *text = text.replace(secret.as_str(), REDACTION_MARKER);
                }
            }
        }
        Json::Array(items) => items.iter_mut().for_each(|item| redact_json(item, secrets)),
        Json::Object(members) => members
            .iter_mut()
            .for_each(|(_, item)| redact_json(item, secrets)),
        _ => {}
    }
}

fn records_json(records: &[Record]) -> Json {
    Json::Array(records.iter().map(Record::to_json).collect())
}

/// Runs one share command (`run_share`).
pub fn run(args: &Args, cx: &Context<'_>) -> Report {
    payload(args, cx).report(cx.command)
}

fn payload(args: &Args, cx: &Context<'_>) -> Payload {
    if args.since.is_some() && !args.changed {
        return Payload::usage(
            "--since needs --changed",
            crate::envelope::code::USAGE_MISSING_OPTION,
            "--changed",
        );
    }
    if args
        .since
        .as_deref()
        .is_some_and(|since| since.trim().is_empty())
    {
        return Payload::usage(
            "--since needs a commit SHA or ref",
            USAGE_INVALID_VALUE,
            "--since",
        );
    }
    if args.workers < 1 {
        return Payload::usage(
            "workers must be at least 1",
            USAGE_INVALID_VALUE,
            "--workers",
        );
    }
    let mut unknown: Vec<&String> = args
        .types
        .iter()
        .filter(|kind| !OBJECT_FAMILIES.contains(&kind.as_str()))
        .collect();
    unknown.sort();
    unknown.dedup();
    if !unknown.is_empty() {
        let listed: Vec<&str> = unknown.iter().map(|kind| kind.as_str()).collect();
        return Payload::usage(
            &format!(
                "Unknown object type(s): {}. Choose threat, objective, or rule.",
                listed.join(", ")
            ),
            USAGE_INVALID_CHOICE,
            "--type",
        );
    }
    let (_, options) = placement(cx.repo, cx.env, cx.cwd);
    let workspace = match super::open(options) {
        Ok(workspace) => workspace,
        Err(message) => return Payload::result(&message, 1, "failed", Vec::new()),
    };
    let sharing = config::load(&workspace, cx.env);
    let secrets = sharing.secrets();
    shared(args, cx, &workspace, &sharing).redacted(&secrets)
}

fn shared(args: &Args, cx: &Context<'_>, workspace: &Workspace, sharing: &Sharing) -> Payload {
    if !sharing.errors().is_empty() {
        let mut payload = Payload::result(
            preflight_message("sharing_config"),
            1,
            "failed",
            sharing.warnings(),
        );
        payload.put("preflight", Json::str("sharing_config"));
        payload.put(
            "issues",
            Json::Array(
                sharing
                    .errors()
                    .iter()
                    .map(|issue| Json::str(&issue.message))
                    .collect(),
            ),
        );
        return payload;
    }
    if args.mode == Mode::Targets {
        return targets_payload(sharing);
    }
    let env_get = |name: &str| cx.env.get(name).map(str::to_owned);
    if args.changed && args.mode == Mode::Push {
        let ci = opentide_compile::git::ci(&env_get);
        let problem = if ci == opentide_compile::git::Ci::Local {
            args.since.is_none().then_some("changed_outside_ci")
        } else if opentide_compile::git::is_change_request(ci, &env_get) {
            Some("changed_on_pull_request")
        } else {
            None
        };
        if let Some(problem) = problem {
            return Payload::preflight(problem, sharing, &[], None);
        }
    }
    let effective = if args.dry_run && args.mode == Mode::Push {
        Mode::Preview
    } else {
        args.mode
    };
    let names: Vec<&str> = sharing
        .blocks
        .iter()
        .map(|block| block.name.as_str())
        .collect();
    if let Some(missing) = args
        .targets
        .iter()
        .find(|name| !names.contains(&name.as_str()))
    {
        let listed = if names.is_empty() {
            "none configured".to_owned()
        } else {
            names.join(", ")
        };
        let mut payload = Payload::usage(
            &format!(
                "Unknown sharing target {}. Configured targets: {listed}.",
                opentide_schema::configuration::repr::quote(missing)
            ),
            USAGE_INVALID_CHOICE,
            "--target",
        );
        payload.put("preflight", Json::str("scope_no_match"));
        payload.put("records", Json::Array(Vec::new()));
        payload.warnings = sharing.warnings();
        payload.failure_suggestion =
            opentide_core::suggest::closest(missing, names.iter().copied()).map(str::to_owned);
        return payload;
    }
    let Some(selected) = select_blocks(&sharing.blocks, &args.targets) else {
        if args.changed && args.mode == Mode::Push && args.targets.is_empty() {
            return Payload::quiet(NO_ENABLED_TARGET, sharing);
        }
        if sharing.blocks.is_empty() {
            let mut payload = Payload::preflight("scope_no_match", sharing, &[], Some(NO_TARGET));
            payload.put("advice", Json::str(ADD_TARGET));
            return payload;
        }
        return Payload::preflight("scope_no_match", sharing, &[], None);
    };
    let documents = document::catalogue(workspace);
    let nested: Vec<String> = super::generate::nested_warning(workspace)
        .into_iter()
        .collect();
    let mut filters = filters(workspace.root(), &args.uuids, &args.types, &args.files);
    if args.changed && args.mode == Mode::Push {
        // Reading the push's diff up to HEAD (`changed_through_head`) is not
        // ported: the oracle runs it.
        let _ = &mut filters;
        return Payload {
            unported: Some(
                "share push --changed reads a git diff this engine does not read".into(),
            ),
            ..Payload::default()
        };
    }
    let ledger = ledger::Ledger::load(&ledger::path(workspace.root()));
    let mut validator = None;
    if effective == Mode::Push {
        validator = Some(engine::Validator::new(workspace, &documents));
    }
    let factory = |block: &Block| -> Result<Box<dyn Misp>, MispCallError> {
        let key = block.resolved_api_key().ok_or_else(|| {
            MispCallError::new(
                opentide_connectors::misp::Kind::Other,
                "api_key_unset",
                None,
            )
        })?;
        let environment = Environment::from_pairs(cx.env.iter());
        MispClient::new(
            &block.name,
            &block.url,
            key,
            block.verify_ssl,
            &environment,
            cx.proxy,
            cx.version,
        )
        .map(|client| Box::new(client) as Box<dyn Misp>)
    };
    let outcome = engine::run(
        &documents,
        &selected,
        &engine::Options {
            mode: effective,
            filters: filters.as_ref(),
            publish: args.publish,
            workers: usize::try_from(args.workers).unwrap_or(1),
            delete: args.delete,
            confirmed: args.yes,
            validator: validator.as_ref(),
            stamp: crate::app::utc_now().0,
        },
        ledger,
        &factory,
    );
    let names = object_names(workspace);
    from_run(&outcome, sharing, effective, &names).with_warnings(&nested)
}

/// The destinations the run uses (`_select_blocks`); `None` is
/// `scope_no_match`.
fn select_blocks(blocks: &[Block], targets: &[String]) -> Option<Vec<Block>> {
    if !targets.is_empty() {
        let mut chosen: Vec<Block> = Vec::new();
        for name in targets {
            let block = blocks.iter().find(|block| &block.name == name)?;
            if !block.enabled {
                return None;
            }
            if !chosen.iter().any(|seen| seen.name == block.name) {
                chosen.push(block.clone());
            }
        }
        return Some(chosen);
    }
    let enabled: Vec<Block> = blocks
        .iter()
        .filter(|block| block.enabled)
        .cloned()
        .collect();
    (!enabled.is_empty()).then_some(enabled)
}

/// The filters the run's options make (`_filters`); `None` when none narrows.
fn filters(
    workspace: &Path,
    uuids: &[String],
    types: &[String],
    files: &[String],
) -> Option<Filters> {
    if uuids.is_empty() && types.is_empty() && files.is_empty() {
        return None;
    }
    let files = (!files.is_empty()).then(|| {
        files
            .iter()
            .map(|item| {
                let path = PathBuf::from(item);
                let path = if path.is_absolute() {
                    path
                } else {
                    workspace.join(path)
                };
                document::resolve(&path)
            })
            .collect()
    });
    Some(Filters {
        uuids: (!uuids.is_empty()).then(|| uuids.to_vec()),
        types: (!types.is_empty()).then(|| types.to_vec()),
        files,
    })
}

/// The objects' names by UUID (`_object_names`).
fn object_names(workspace: &Workspace) -> BTreeMap<String, String> {
    let mut names = BTreeMap::new();
    for family in workspace.index().objects.values() {
        for (uuid, object) in family {
            if let Some(name) = object
                .root()
                .and_then(|root| root.get("name"))
                .and_then(|name| name.value.as_str())
                .filter(|name| !name.is_empty())
            {
                names.insert(uuid.clone(), name.to_owned());
            }
        }
    }
    names
}

/// `share targets`' payload (`_targets_payload`).
fn targets_payload(sharing: &Sharing) -> Payload {
    let rows: Vec<Json> = sharing
        .blocks
        .iter()
        .map(|block| {
            Json::object([
                ("integration", Json::str(config::INTEGRATION_MISP)),
                ("name", Json::str(&block.name)),
                ("enabled", Json::Bool(block.enabled)),
                ("max_tlp", Json::str(&block.max_tlp)),
                ("url", Json::str(&block.url)),
            ])
        })
        .collect();
    let count = rows.len();
    let mut payload = Payload::result(
        &format!(
            "{count} sharing target{}",
            if count == 1 { "" } else { "s" }
        ),
        0,
        "completed",
        sharing.warnings(),
    );
    payload.put("targets", Json::Array(rows));
    if count == 0 {
        payload.status = "skipped".into();
        payload.outcome = Some(NO_TARGET.to_owned());
        payload.put("advice", Json::str(ADD_TARGET));
    } else {
        let (bold, dim) = (Style::new("bold"), Style::new("dim"));
        let rows: Vec<Vec<Text>> = sharing
            .blocks
            .iter()
            .map(|block| {
                vec![
                    Text::styled(&block.name, &bold),
                    Text::styled(config::INTEGRATION_MISP, &dim),
                    Text::styled(if block.enabled { "enabled" } else { "disabled" }, &dim),
                    Text::styled(&format!("max TLP {}", block.max_tlp), &dim),
                    Text::styled(&block.url, &dim),
                ]
            })
            .collect();
        payload.body = vec![BodyBlock::Hanging(
            columns(&rows, 2, 0, &[])
                .into_iter()
                .map(|line| (line, 2))
                .collect(),
        )];
    }
    payload
}

/// The word a record's action counts under (`_ACTION_WORDS`).
fn action_word(action: &str) -> &str {
    match action {
        "created" => "new",
        "skipped_tlp" | "skipped_status" | "skipped_type" => "skipped",
        other => other,
    }
}

/// `Shared 4 objects to misp-prod · 3 new, 1 updated`, and the counts
/// behind it (`share_outcome`).
fn share_outcome(mode: Mode, records: &[Record]) -> (String, Vec<(String, Json)>) {
    let mut targets: Vec<&str> = records
        .iter()
        .map(|record| record.target.as_str())
        .collect();
    targets.sort_unstable();
    targets.dedup();
    let targets = if targets.is_empty() {
        "no target".to_owned()
    } else {
        targets.join(", ")
    };
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for record in records {
        *counts.entry(action_word(&record.action)).or_default() += 1;
    }
    let mut sent: Vec<&str> = records
        .iter()
        .filter(|record| matches!(record.action.as_str(), "created" | "updated" | "retracted"))
        .map(|record| record.object_uuid.as_str())
        .collect();
    sent.sort_unstable();
    sent.dedup();
    let done = sent.len();
    let objects = plural(done, "object", None);
    let mut lead = match mode {
        Mode::Push => format!("Shared {objects} to {targets}"),
        Mode::Preview => format!("Would share {objects} to {targets}"),
        Mode::Retract => format!("Retracted {objects} from {targets}"),
        _ => {
            let mut all: Vec<&str> = records
                .iter()
                .map(|record| record.object_uuid.as_str())
                .collect();
            all.sort_unstable();
            all.dedup();
            format!("{} on {targets}", plural(all.len(), "object", None))
        }
    };
    if done == 0
        && !records.is_empty()
        && matches!(mode, Mode::Push | Mode::Preview | Mode::Retract)
    {
        lead = if mode == Mode::Retract {
            "Nothing to retract".to_owned()
        } else {
            "Nothing to share".to_owned()
        };
    }
    let order = [
        "new",
        "updated",
        "unchanged",
        "retracted",
        "skipped",
        "failed",
    ];
    let facts: Vec<String> = order
        .iter()
        .filter_map(|word| {
            counts
                .get(word)
                .filter(|count| **count > 0)
                .map(|count| format!("{count} {word}"))
        })
        .collect();
    let mut summary: Vec<(String, Json)> = vec![("objects".into(), Json::from(done))];
    for word in order {
        summary.push((
            word.into(),
            Json::from(counts.get(word).copied().unwrap_or(0)),
        ));
    }
    let message = if facts.is_empty() {
        lead
    } else {
        format!("{lead} · {}", facts.join(", "))
    };
    (message, summary)
}

/// The payload of a run that reached the engine (`_from_run`).
fn from_run(
    outcome: &ShareRun,
    sharing: &Sharing,
    mode: Mode,
    names: &BTreeMap<String, String>,
) -> Payload {
    if let Some(preflight) = &outcome.preflight {
        let mut payload = Payload::preflight(preflight, sharing, &outcome.records, None);
        payload.body = rows(&outcome.records, false, names);
        return payload;
    }
    let code = outcome.exit_code();
    let failed = code != 0;
    let (message, summary) = share_outcome(mode, &outcome.records);
    let mut payload = Payload::result(
        &message,
        code,
        if failed { "failed" } else { "completed" },
        sharing.warnings(),
    );
    payload.put("records", records_json(&outcome.records));
    payload.summary = summary;
    if failed {
        payload.failure_code = Some(
            match code {
                2 => "share_unreachable",
                3 => "share_partial",
                _ => "share_failed",
            }
            .to_owned(),
        );
    } else if mode == Mode::Preview {
        payload.plan = true;
    }
    // A preview's rows say what would happen only when it is a plan: one with
    // a failure is rendered as a result (`_outcome_kind`).
    payload.body = rows(&outcome.records, payload.plan, names);
    payload
}

/// A record's glyph, labels and style (`_SHARE_ROWS`).
fn row_style(action: &str) -> (&'static str, &str, &str, &'static str) {
    match action {
        "created" => ("+", "create", "created", "bold green"),
        "updated" => ("~", "update", "updated", "bold yellow"),
        "unchanged" => (glyphs::SKIP, "unchanged", "unchanged", "dim"),
        "retracted" => ("×", "retract", "retracted", "bold red"),
        "skipped_tlp" | "skipped_status" | "skipped_type" => {
            (glyphs::SKIP, "skip", "skipped", "dim")
        }
        "failed" => (glyphs::FAILED, "fail", "failed", "bold red"),
        other => (glyphs::SKIP, other, other, "dim"),
    }
}

/// Why an object was skipped, in words (`_SKIP_REASONS`).
fn skip_reason(reason: &str) -> String {
    match reason {
        "max_tlp" => "TLP above max_tlp".to_owned(),
        "object_type" => "type not shared".to_owned(),
        "rule_status" => "status not shared".to_owned(),
        other => other.replace('_', " "),
    }
}

/// The records as plan rows, by destination (`render_share`).
fn rows(records: &[Record], preview: bool, names: &BTreeMap<String, String>) -> Vec<BodyBlock> {
    let mut targets: Vec<(&str, Vec<&Record>)> = Vec::new();
    for record in records {
        match targets.iter_mut().find(|(name, _)| *name == record.target) {
            Some((_, members)) => members.push(record),
            None => targets.push((&record.target, vec![record])),
        }
    }
    let (bold, dim) = (Style::new("bold"), Style::new("dim"));
    let mut body = Vec::new();
    for (target, members) in targets {
        let mut title = Text::styled(target, &bold);
        if preview {
            title.append(
                &format!(" {} dry run, nothing is sent", glyphs::SEPARATOR),
                &dim,
            );
            // The title's own style is bold, under the dim part too (a Rich
            // `Text` with a base style).
            let length = title.len();
            title.stylize(&bold, 0, length);
        }
        body.push(BodyBlock::Hanging(vec![(title, 0)]));
        let lines: Vec<Vec<Text>> = members
            .iter()
            .map(|record| {
                let (mark, planned, done, style) = row_style(&record.action);
                let why = record
                    .reason
                    .as_deref()
                    .map(skip_reason)
                    .unwrap_or_default();
                vec![
                    Text::styled(
                        &format!("{mark} {}", if preview { planned } else { done }),
                        &Style::new(style),
                    ),
                    Text::styled(
                        names
                            .get(&record.object_uuid)
                            .map_or(record.object_uuid.as_str(), String::as_str),
                        &bold,
                    ),
                    Text::styled(&super::deploy::short_uuid(&record.object_uuid), &dim),
                    Text::styled(&why, &dim),
                ]
            })
            .collect();
        body.push(BodyBlock::Hanging(
            columns(&lines, 2, 2, &[])
                .into_iter()
                .map(|line| (line, 6))
                .collect(),
        ));
        body.push(BodyBlock::Hanging(vec![(Text::plain(""), 0)]));
    }
    body
}

/// The documents of the catalogue, for tests.
#[cfg(test)]
pub(crate) fn documents_for_test(texts: &[(&str, &str)]) -> Vec<document::TideDocument> {
    texts
        .iter()
        .map(|(path, text)| document::load(text.as_bytes(), Some(PathBuf::from(path))))
        .collect()
}
