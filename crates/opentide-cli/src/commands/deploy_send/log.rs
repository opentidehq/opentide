//! The record phase of a run: each rule's result, the counts and summary
//! the result carries, and the log printed on stderr as rules finish.

use std::collections::HashMap;
use std::time::Instant;

use anstyle::{AnsiColor, Style};
use indexmap::IndexMap;
use opentide_compile::plan::Change;

use super::{
    DONE, Lines, MAX_ERROR_LENGTH, MAX_ERROR_LINES, MIN_ERROR_WIDTH, NAME_WIDTH, NOT_ATTEMPTED,
    VERBS, reached,
};
use crate::json::{Json, Object};
use crate::render::glyphs;
use crate::render::progress::{plural, seconds_text};
use crate::render::text::Text;

// ------------------------------------------------------------------ results

/// One rule on one tenant: what was sent and how it went (`RuleResult`).
#[derive(Clone, Debug)]
pub(super) struct RuleResult {
    pub(super) platform: String,
    pub(super) tenant: Option<String>,
    pub(super) id: String,
    pub(super) name: String,
    pub(super) status: &'static str,
    pub(super) action: Option<String>,
    pub(super) seconds: Option<f64>,
    pub(super) error: Option<String>,
    reason: Option<String>,
    /// Old copies the platform deleted beside the rule (a renamed Splunk
    /// rule's saved searches).
    pub(super) removed: Vec<String>,
    /// A rule whose file is gone, retired by `--prune` (#1713).
    pub(super) retired: bool,
    started: Instant,
}

impl RuleResult {
    pub(super) fn new(platform: &str, tenant: Option<&str>, id: &str, name: &str) -> Self {
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
            removed: Vec::new(),
            retired: false,
            started: Instant::now(),
        }
    }

    /// Records a failure the deployer reports without raising (`fail`).
    pub(super) fn fail(&mut self, error: &str) {
        if self.status != "failed" {
            self.status = "failed";
            self.error = Some(bounded(error));
        }
    }

    /// Records that the engine chose not to send it (`skip`).
    pub(super) fn skip(&mut self, reason: &str) {
        if self.status != "failed" {
            self.status = "skipped";
            self.reason = Some(reason.to_owned());
        }
    }

    /// The row `results` carries (`to_dict`).
    pub(super) fn to_json(&self) -> Json {
        let text = |value: &Option<String>| value.as_ref().map_or(Json::Null, Json::str);
        let mut members = vec![
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
        ];
        // Only a rule that deleted an old copy says so (#1657).
        if !self.removed.is_empty() {
            members.push((
                "removed",
                Json::Array(self.removed.iter().map(Json::str).collect()),
            ));
        }
        // Only a rule whose file is gone says so (#1713).
        if self.retired {
            members.push(("retired", Json::Bool(true)));
        }
        Json::object(members)
    }
}

/// *text* on one line, cut at [`MAX_ERROR_LENGTH`] (`_bounded`).
pub(super) fn bounded(text: &str) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() > MAX_ERROR_LENGTH {
        let cut: String = text.chars().take(MAX_ERROR_LENGTH - 1).collect();
        return format!("{}…", cut.trim_end());
    }
    text
}

/// `2 deployed, 1 failed, 88 not attempted` (`counts_text`).
pub(super) fn counts_text(results: &[&RuleResult]) -> String {
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

/// The `summary` of a real run (`run_summary`).
pub(super) fn run_summary(
    results: &[RuleResult],
    platforms: usize,
    tenants: usize,
    seconds: f64,
) -> Object {
    let counts = run_counts(results);
    let mut members: Object = counts
        .iter()
        .map(|(key, count)| ((*key).to_owned(), Json::from(*count)))
        .collect();
    members.insert(
        "seconds".into(),
        Json::Float((seconds * 1000.0).round() / 1000.0),
    );
    members.insert("platforms".into(), Json::from(platforms));
    members.insert("tenants".into(), Json::from(tenants));
    members
}

/// The run's last line, for a pass and for a failure alike (`outcome_message`).
pub(super) fn outcome_message(results: &[RuleResult], seconds: f64, failed: bool) -> String {
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

/// The plan a [`DeployLog`] follows: each tenant's planned changes and each
/// rule's planned action, shared by the log of every tenant.
pub(super) struct LogPlan {
    pub(super) planned: IndexMap<Key, Vec<Change>>,
    actions: HashMap<(String, Option<String>, String), String>,
}

impl LogPlan {
    pub(super) fn new(changes: &[Change]) -> Self {
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
        Self { planned, actions }
    }
}

/// Follows a deploy: one line per finished rule (`DeployLog`).
pub(super) struct DeployLog<'l> {
    lines: &'l Lines,
    pub(super) results: Vec<RuleResult>,
    pub(super) planned: &'l IndexMap<Key, Vec<Change>>,
    actions: &'l HashMap<(String, Option<String>, String), String>,
    printed: HashMap<Key, usize>,
    /// While tenants deploy at once: the header the last row was printed
    /// under, which every log of the run shares, so a row of another tenant
    /// prints its own header again first. `None` one tenant after another:
    /// each header prints once.
    interleaved: Option<std::sync::Arc<std::sync::Mutex<Option<Key>>>>,
}

impl<'l> DeployLog<'l> {
    pub(super) fn new(lines: &'l Lines, plan: &'l LogPlan) -> Self {
        Self {
            lines,
            results: Vec::new(),
            planned: &plan.planned,
            actions: &plan.actions,
            printed: HashMap::new(),
            interleaved: None,
        }
    }

    /// An empty log of the same plan, for one tenant's deploy: its results
    /// and the lines it printed are its own until [`merge`](Self::merge)
    /// adds them here.
    pub(super) fn fork(&self) -> Self {
        Self {
            lines: self.lines,
            results: Vec::new(),
            planned: self.planned,
            actions: self.actions,
            printed: HashMap::new(),
            interleaved: self.interleaved.clone(),
        }
    }

    /// From now on, rows may interleave with other tenants': each row whose
    /// header is not the last printed prints it again first.
    pub(super) fn interleave(&mut self) {
        self.interleaved
            .get_or_insert_with(|| std::sync::Arc::new(std::sync::Mutex::new(None)));
    }

    /// Adds a tenant's log ([`fork`](Self::fork)) after the results here:
    /// its results in the order they ended, and the lines it printed.
    pub(super) fn merge(&mut self, tenant: Self) {
        self.results.extend(tenant.results);
        for (key, printed) in tenant.printed {
            *self.printed.entry(key).or_default() += printed;
        }
    }

    /// A rule ended (`rule_finished`).
    pub(super) fn finished(&mut self, mut result: RuleResult) {
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
        if reached(&result) {
            // Kept promoted from now on, whatever ends the run (#1653).
            super::super::deploy_promote::received(&opentide_compile::rule::canonical_uuid(
                &result.id,
            ));
        }
        self.print(&result);
        self.results.push(result);
    }

    /// The plan's action for a rule on a tenant (else on its platform).
    pub(super) fn planned_action(
        &self,
        platform: &str,
        tenant: Option<&str>,
        id: &str,
    ) -> Option<&str> {
        [tenant.map(str::to_owned), None]
            .into_iter()
            .find_map(|tenant| {
                self.actions
                    .get(&(platform.to_owned(), tenant, id.to_owned()))
            })
            .map(String::as_str)
    }

    /// A rule planning refused before anything was sent (`refused`).
    pub(super) fn refused(
        &mut self,
        platform: &str,
        tenant: &str,
        id: &str,
        name: &str,
        error: &str,
    ) {
        let mut result = RuleResult::new(platform, Some(tenant), id, name);
        result.status = "failed";
        result.error = Some(bounded(error));
        result.seconds = Some(0.0);
        self.finished(result);
    }

    /// A rule the engine decided not to send (`skipped`).
    pub(super) fn skipped(
        &mut self,
        platform: &str,
        tenant: &str,
        id: &str,
        name: &str,
        reason: &str,
    ) {
        let mut result = RuleResult::new(platform, Some(tenant), id, name);
        result.status = "skipped";
        result.reason = Some(reason.to_owned());
        result.seconds = Some(0.0);
        self.finished(result);
    }

    /// Whether a rule of *tenant* on *platform* was deployed.
    pub(super) fn deployed_on(&self, platform: &str, tenant: &str) -> bool {
        self.results.iter().any(|result| {
            result.platform == platform
                && result.tenant.as_deref() == Some(tenant)
                && result.status == "deployed"
        })
    }

    /// A rule no tenant of `platform` takes: skipped before anything is
    /// sent, with no tenant.
    pub(super) fn unrouted(&mut self, platform: &str, id: &str, name: &str, reason: &str) {
        let mut result = RuleResult::new(platform, None, id, name);
        result.status = "skipped";
        result.reason = Some(reason.to_owned());
        result.seconds = Some(0.0);
        self.finished(result);
    }

    pub(super) fn platform_results(&self, platform: &str) -> Vec<&RuleResult> {
        self.results
            .iter()
            .filter(|result| result.platform == platform)
            .collect()
    }

    /// A platform returned without raising (`settle`).
    pub(super) fn settle(&mut self, platform: &str) {
        let mine = self.platform_results(platform);
        if mine.is_empty() {
            let mut added = Vec::new();
            for ((name, tenant), changes) in self.planned {
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
    pub(super) fn unreached(&mut self, platform: Option<&str>, status: &'static str, reason: &str) {
        self.unreached_where(platform, None, status, reason);
    }

    /// Reports each rule planned on one tenant that has no result.
    pub(super) fn unreached_on(
        &mut self,
        platform: &str,
        tenant: &str,
        status: &'static str,
        reason: &str,
    ) {
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
        for ((name, planned_on), changes) in self.planned {
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
        // Held until the row is printed: no other tenant's row comes
        // between the header and it.
        let mut last = self.interleaved.as_ref().map(|last| {
            last.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        });
        let other_tenant = last
            .as_deref()
            .is_some_and(|last| last.as_ref() != Some(&key));
        if !self.printed.contains_key(&key) || other_tenant {
            self.lines.line(&Text::default(), false);
            self.lines.line(
                &header_line(
                    &key.0,
                    key.1.as_deref(),
                    (total_planned > 0).then_some(total_planned),
                ),
                false,
            );
            self.printed.entry(key.clone()).or_insert(0);
        }
        if let Some(last) = last.as_deref_mut() {
            *last = Some(key.clone());
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
pub(super) fn header_line(platform: &str, tenant: Option<&str>, rules: Option<usize>) -> Text {
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
pub(super) fn verb(result: &RuleResult) -> &'static str {
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
pub(super) fn result_line(
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
