//! The plan phase of a run and what wraps it: the workspace opened, the
//! changes planned, the blocks a status kept out counted, and the files a
//! status promotion rewrote put back unless a tenant received their rule.

use indexmap::IndexMap;
use opentide_compile::Json as CJson;
use opentide_compile::plan::{self, Change};
use opentide_compile::strategy::{self, StatusStrategy};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{OsFs, Workspace, root};

use super::super::placement;
use super::super::result::{CommandResult, ExitCode, Status};
use super::{Args, COMMAND, Context, RuleResult, deploy, refusal};
use crate::envelope::NextAction;
use crate::json::{Json, Object};
use crate::render::glyphs;

/// The run: the plan and the sends, then the warnings and the blocks
/// a status kept out.
pub(super) fn run_deploy(args: &Args, cx: &Context<'_>) -> CommandResult {
    let (_, options) = placement(cx.repo, cx.env, cx.cwd);
    let workspace = match super::super::open_for(COMMAND, options) {
        Ok(workspace) => workspace,
        Err(refused) => {
            // A TOML file that does not parse keeps `config_parse`.
            let (code, message, diagnostics) = super::super::refusal_parts(&refused);
            return refusal(code, &message, diagnostics);
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
        result.data.insert("retirable".into(), retirable);
    }
    if (!args.uuids.is_empty() || !args.files.is_empty()) && result.get("scope").is_none() {
        result.data.insert("scope".into(), Json::str("selected"));
    }
    let unread = opentide_compile::dry_run::unread_files(&workspace, cx.cwd);
    if !unread.is_empty() {
        warnings.push(format!(
            "{} could not be read: {}; opentide validate shows where",
            plan::plural(unread.len(), "object file"),
            unread.join(", ")
        ));
    }
    // The run's warnings, then the result's own.
    if !warnings.is_empty() {
        warnings.append(&mut result.warnings);
        result.warnings = warnings;
    }
    if !skipped.is_empty() {
        report_skipped(&mut result, &skipped, &workspace, &args.strategies);
    }
    if result.status == Status::Skipped
        && result.next_actions.is_empty()
        && !root::is_workspace_root(&OsFs, workspace.root())
    {
        result.next_actions.push(NextAction::new(
            "opentide setup",
            "no workspace here: create one",
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
fn run_strategies(result: &Object) -> Vec<StatusStrategy> {
    match result.get("strategies") {
        Some(Json::Array(items)) => items
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
    result: &mut CommandResult,
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
    let mut runs = run_strategies(&result.data);
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
    result.data.insert(
        "skipped".into(),
        Json::Array(skipped.iter().map(|entry| entry.to_json()).collect()),
    );
    // The rows the run skipped (a rule no tenant takes, an `INERT` block),
    // and the rules a status left out that have no such row: a rule is
    // never counted twice.
    let rows = match result.summary.get("skipped") {
        Some(Json::Int(rows)) => usize::try_from(*rows).unwrap_or(0),
        _ => 0,
    };
    let skipped_rows: std::collections::HashSet<String> = match result.get("results") {
        Some(Json::Array(rows)) => rows
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
    result
        .summary
        .insert("skipped".to_owned(), Json::from(rows + left.len()));
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
        result.get("plan"),
        Some(Json::Object(members)) if !members.is_empty()
    );
    if result.status == Status::Skipped && !planned {
        result.outcome_line = Some(format!(
            "No rule has a status {run_names} deploys {} {in_status}",
            glyphs::SEPARATOR
        ));
        if result.get("advice").is_none() {
            result.data.insert("advice".into(), Json::str(advice));
        }
    } else if result.get("detail").is_none() {
        result.data.insert(
            "detail".into(),
            Json::str(format!("not in the plan: {in_status}; {advice}")),
        );
    }
}

/// The files a status promotion rewrote: put back as they were before the
/// result is built ([`Unpromote::finish`]) unless a tenant received their
/// rule, so the write-back commits no status that was never deployed
/// (#1653). A file is kept promoted when any platform block of its rule
/// reached any tenant. Dropping the guard puts back what `finish` did not
/// (a panic); a forced exit puts back what is still pending
/// ([`super::super::deploy_promote::restore_pending`]).
#[derive(Default)]
pub(super) struct Unpromote {
    pub(super) files: Vec<super::super::deploy_promote::Promoted>,
    /// The canonical UUIDs of the rules a tenant received.
    sent: std::collections::HashSet<String>,
}

/// What putting the promoted files back did: warnings for the files left
/// as they were, failures for the files that could not be written.
#[derive(Debug, Default)]
pub(super) struct Settled {
    pub(super) warnings: Vec<String>,
    pub(super) failures: Vec<(String, String)>,
}

impl Unpromote {
    /// The rules of `results` a tenant received (`deployed`): their files
    /// are kept promoted, and a forced exit no longer puts them back.
    pub(super) fn received(&mut self, results: &[RuleResult]) {
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
        super::super::deploy_promote::settle(&kept);
    }

    fn keeps(&self, file: &super::super::deploy_promote::Promoted) -> bool {
        file.uuid
            .as_ref()
            .is_some_and(|uuid| self.sent.contains(uuid))
    }

    /// Puts back every file no tenant received the rule of, once, holding
    /// the pending files' lock: a signal meanwhile waits for it, then finds
    /// nothing left to put back.
    fn finish(&mut self) -> Settled {
        use super::super::deploy_promote::Restored;
        let files = std::mem::take(&mut self.files);
        let mut settled = Settled::default();
        // Restored under the pending lock, logged once it is released: a
        // log line may wait for stderr, which a signal's thread can hold
        // while it waits for the pending files.
        let mut undone = Vec::new();
        let mut held = super::super::deploy_promote::pending();
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
pub(super) fn reached(result: &RuleResult) -> bool {
    result.status == "deployed" && result.tenant.is_some()
}

impl Settled {
    /// The run's result with the files left as they were among its
    /// warnings, and a file that could not be put back as a failure: the
    /// run fails (exit 1), since a commit would carry a status no tenant
    /// received.
    pub(super) fn apply(self, result: &mut CommandResult, warnings: &mut Vec<String>) {
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
        let mut all = match result.get("failures") {
            Some(Json::Array(own)) => own.clone(),
            _ => Vec::new(),
        };
        all.extend(entries);
        result.set("failures", Json::Array(all));
        if result.status != Status::Failed {
            result.status = Status::Failed;
            result.message = Some(lines[0].clone());
            result.set("error", Json::str(&lines[0]));
        }
        result.exit = ExitCode::Failure;
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
pub(super) fn plan_changes(
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
