//! Deploys YARA-L rules to Google Security Operations, ported from 0.28.0's
//! `platforms/google_secops/deployer.py`, request for request.
//!
//! Google assigns every rule an id (`ru_<uuid>`) at create time; deployment
//! state keeps it, and every create, update, disable, archive and delete is
//! planned from it: deploy never lists rules nor finds one by name. Each
//! create and each text update is compiled by `verifyRuleText` first; an
//! unchanged text is never sent again, so the rule keeps its revision. A
//! bound rule is unarchived first, and its text, `scope` and run state are
//! each updated only where they differ. `PREVIEW` runs the rule without
//! alerting, `RELEASE` and `UNIVERSAL` alert, `DISABLEMENT` disables it, and
//! `DELETION` archives it, or deletes it without `force` when the tenant
//! asks (archiving it when Google refuses). A create is never sent again
//! after a 5xx or no answer.

use opentide_compile::Json;
use opentide_compile::google_secops::{RunState, scope_id};
use opentide_schema::objects::platform::google_secops::assemble::AssembledRule;

use crate::connector::TenantContext;
use crate::error::ConnectorError;

use super::auth::Authorizer;
use super::client::{ApiError, Client, Failure};
use super::diagnostics::{VerifyOutcome, describe_diagnostic, read_verify_answer};

/// What a deploy does to the rule on the tenant (`ExternalIdAction`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// No id is recorded: create the rule.
    Create,
    /// The recorded id: update the rule, or disable it.
    Update(String),
    /// The recorded id, under a DELETION status: archive or delete it.
    Delete(String),
}

/// One rule to deploy to one instance.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleDeploy {
    /// What to do.
    pub action: Action,
    /// The assembled rule (`opentide-compile`'s `google_secops::assemble`).
    pub assembled: AssembledRule,
    /// The run state the block's status strategy deploys (`run_state`).
    pub run_state: RunState,
    /// The block's `run_frequency`, when it names one.
    pub run_frequency: Option<String>,
    /// The strategy is DISABLEMENT.
    pub disabling: bool,
    /// The strategy is DISABLEMENT or DELETION: a lost rule is forgotten,
    /// not created again.
    pub retiring: bool,
    /// The tenant's `data_access_scope` as a resource name.
    pub scope: Option<String>,
    /// The tenant's `deletion` is `delete`.
    pub delete: bool,
    /// Why deployment state cannot take a rule created again, when it
    /// cannot (`deployment_state_ignore`, `unpersisted_error`): its code and
    /// message.
    pub recreate_refusal: Option<(String, String)>,
}

/// What deployment state makes of a deploy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateChange {
    /// Nothing changes.
    Keep,
    /// Record the id Google gave the rule (`record_created`).
    Record(String),
    /// Forget the rule's id (`record_deleted`).
    Forget,
}

/// A warning a deploy raises (`_deployment_warning`), or a log line worth
/// keeping (`google_secops_compile_warning`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// The code.
    pub code: &'static str,
    /// What happened.
    pub detail: String,
}

/// A failure of this rule (`_deployment_error`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleFailure {
    /// The code (`google_secops_verify_failed`, `google_secops_request_failed`, …).
    pub code: String,
    /// What failed.
    pub message: String,
}

/// What a deploy of one rule did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleOutcome {
    /// The deployment-state change, made whether a later request failed or
    /// not (a create is recorded before its run state is set).
    pub state: StateChange,
    /// Warnings raised, in order.
    pub warnings: Vec<Warning>,
    /// Failures, in order: under DISABLEMENT a failed text update fails the
    /// rule and the rule is disabled all the same.
    pub failures: Vec<RuleFailure>,
}

impl RuleOutcome {
    fn fail(&mut self, code: &str, message: impl Into<String>) {
        self.failures.push(RuleFailure {
            code: code.to_owned(),
            message: message.into(),
        });
    }

    fn warn(&mut self, code: &'static str, detail: impl Into<String>) {
        self.warnings.push(Warning {
            code,
            detail: detail.into(),
        });
    }

    fn request_failed(&mut self, error: &ApiError) {
        self.fail("google_secops_request_failed", error.short());
    }

    fn deployment_failed(&mut self, rule_id: &str, error: &ApiError) {
        self.fail(
            "google_secops_deployment_failed",
            format!(
                "rule {rule_id} is bound, but its run state could not be set ({error}); the next \
                 deploy repairs it"
            ),
        );
    }

    /// A text or scope update Google refused: a stale `etag` is a conflict.
    fn write_failed(&mut self, rule_id: &str, error: &ApiError) {
        if error.conflict() {
            self.fail(
                "google_secops_rule_conflict",
                format!(
                    "rule {rule_id} changed between its read and the update (etag mismatch); \
                     nothing was written. Deploy again"
                ),
            );
        } else {
            self.request_failed(error);
        }
    }
}

/// The `ru_<uuid>` id at the end of a rule resource `name`, or `None`.
pub fn returned_rule_id(name: Option<&Json>) -> Option<String> {
    let name = name?.as_str()?.trim();
    let id = name.rsplit('/').next()?;
    let uuid = id.strip_prefix("ru_")?;
    let groups: Vec<&str> = uuid.split('-').collect();
    let shape = [8, 4, 4, 4, 12];
    (groups.len() == shape.len()
        && groups.iter().zip(shape).all(|(group, length)| {
            group.len() == length
                && group
                    .chars()
                    .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
        }))
    .then(|| id.to_owned())
}

fn etag(remote: &Json) -> Option<String> {
    remote
        .get("etag")
        .filter(|value| value.truthy())
        .map(opentide_compile::deploy::text)
}

/// `RuleDeployment.executionState` values under which Google does not run
/// the rule as asked.
const LIMITED: [&str; 2] = ["LIMITED", "PAUSED"];

/// Warns when Google says it limits, pauses, or cannot compile a bound rule.
fn health(rule: &Json, deployment: &Json, outcome: &mut RuleOutcome) {
    let state = deployment
        .get("executionState")
        .and_then(Json::as_str)
        .unwrap_or_default();
    if LIMITED.contains(&state) {
        outcome.warn(
            "google_secops_rule_execution_limited",
            format!(
                "Google reports the rule's execution as {state}: {}",
                if state == "PAUSED" {
                    "it is not run at all"
                } else {
                    "its runs are not guaranteed"
                }
            ),
        );
    }
    if rule.get("compilationState").and_then(Json::as_str) == Some("FAILED") {
        outcome.warn(
            "google_secops_rule_compilation_failed",
            "Google reports the rule's compilation as FAILED (a compiler change on Google's \
             side); check it with opentide validate query --platform google_secops --live",
        );
    }
}

/// Deploys one rule (`GoogleSecopsDeploy.deploy_rule`). A rule's failure is
/// in the outcome; an `Err` is the tenant's (refused credentials, an
/// instance that cannot be reached), which stops the tenant.
///
/// # Errors
///
/// The tenant's [`ConnectorError`].
pub async fn deploy_rule(
    cx: TenantContext<'_>,
    auth: &Authorizer,
    endpoint: &str,
    instance: &str,
    rule: &RuleDeploy,
) -> Result<RuleOutcome, ConnectorError> {
    let client = Client::new(cx, auth, endpoint, instance);
    let mut outcome = RuleOutcome {
        state: StateChange::Keep,
        warnings: Vec::new(),
        failures: Vec::new(),
    };
    let run = match &rule.action {
        Action::Delete(rule_id) => retire(&client, rule, rule_id, &mut outcome).await,
        Action::Create => create(&client, rule, &mut outcome).await,
        Action::Update(rule_id) => update(&client, rule, rule_id, &mut outcome).await,
    };
    run.map(|()| outcome)
}

/// A failure the rule records, or the tenant's error.
fn api(failure: Failure) -> Result<ApiError, ConnectorError> {
    match failure {
        Failure::Api(error) => Ok(error),
        Failure::Tenant(error) => Err(error),
    }
}

/// `verifyRuleText` on the rule; `None` (and the rule failed) when it does
/// not compile.
async fn verify(
    client: &Client<'_>,
    assembled: &AssembledRule,
    outcome: &mut RuleOutcome,
) -> Result<Option<VerifyOutcome>, ConnectorError> {
    let verified = match client.verify(&assembled.text).await {
        Ok(answer) => read_verify_answer(&answer),
        Err(failure) => {
            outcome.request_failed(&api(failure)?);
            return Ok(None);
        }
    };
    for warning in &verified.warnings {
        outcome.warn(
            "google_secops_compile_warning",
            describe_diagnostic(warning, assembled),
        );
    }
    if verified.ok() {
        return Ok(Some(verified));
    }
    let mut reasons: Vec<String> = verified
        .errors
        .iter()
        .map(|item| describe_diagnostic(item, assembled))
        .collect();
    if reasons.is_empty() {
        reasons.push("verifyRuleText did not report success".to_owned());
    }
    outcome.fail(
        "google_secops_verify_failed",
        format!(
            "Google SecOps does not compile rule {}: {}",
            assembled.name,
            reasons.join("; ")
        ),
    );
    Ok(None)
}

/// Whether Google allows the block's `run_frequency`; the rule fails when
/// it does not. A block that names none sends none.
fn frequency_allowed(rule: &RuleDeploy, allowed: &[String], outcome: &mut RuleOutcome) -> bool {
    match &rule.run_frequency {
        Some(frequency) if !allowed.is_empty() && !allowed.contains(frequency) => {
            outcome.fail(
                "google_secops_run_frequency_not_allowed",
                format!(
                    "run_frequency {frequency} is not one Google allows for this rule ({}); \
                     nothing was written",
                    allowed.join(", ")
                ),
            );
            false
        }
        _ => true,
    }
}

const UNCONFIRMED: &str = "so it may have succeeded with an id opentide does not know. Deploy \
     does not send it again: find the rule in Google SecOps (Detection, Rules) and delete it, or \
     record its ru_ id in .opentide/states/deployment/";

fn create_no_id(outcome: &mut RuleOutcome, assembled: &AssembledRule, answer: &str) {
    outcome.fail(
        "google_secops_create_no_id",
        format!(
            "rules.create for {} answered {answer}, which names no rule id; the rule may exist \
             without a binding",
            assembled.name
        ),
    );
}

async fn create(
    client: &Client<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), ConnectorError> {
    let Some(verified) = verify(client, &rule.assembled, outcome).await? else {
        return Ok(());
    };
    if !frequency_allowed(rule, &verified.allowed, outcome) {
        return Ok(());
    }
    let name = &rule.assembled.name;
    let created = match client
        .create(&rule.assembled.text, rule.scope.as_deref())
        .await
    {
        Ok(created) => created,
        // Sent, and no answer: the rule may exist with an id opentide never saw.
        Err(Failure::Tenant(
            error @ (ConnectorError::Timeout { .. } | ConnectorError::Answer { .. }),
        )) => {
            outcome.fail(
                "google_secops_create_unconfirmed",
                format!("the create of rule {name} got no answer ({error}), {UNCONFIRMED}"),
            );
            return Ok(());
        }
        Err(Failure::Tenant(error)) => return Err(error),
        Err(Failure::Api(error)) => {
            if error.server_error() {
                // A 5xx may come after the rule was written: never resent.
                outcome.fail(
                    "google_secops_create_unconfirmed",
                    format!(
                        "the create of rule {name} answered HTTP {} {}: {}, {UNCONFIRMED}",
                        error.http_status, error.status, error.message
                    ),
                );
            } else if error.http_status < 300 {
                create_no_id(
                    outcome,
                    &rule.assembled,
                    &format!("a body that is not JSON ({})", error.message),
                );
            } else {
                outcome.request_failed(&error);
            }
            return Ok(());
        }
    };
    let Some(rule_id) = returned_rule_id(created.get("name")) else {
        let shown = created
            .get("name")
            .map_or_else(|| "None".to_owned(), python_repr);
        create_no_id(outcome, &rule.assembled, &format!("name {shown}"));
        return Ok(());
    };
    outcome.state = StateChange::Record(rule_id.clone());
    if let Err(failure) = client.update_deployment(&rule_id, &rule.run_state).await {
        outcome.deployment_failed(&rule_id, &api(failure)?);
    }
    Ok(())
}

/// Python's `repr` of a JSON scalar.
fn python_repr(value: &Json) -> String {
    match value {
        Json::Str(text) => opentide_schema::configuration::repr::quote(text),
        Json::Null => "None".to_owned(),
        other => opentide_compile::deploy::text(other),
    }
}

/// A bound rule: read it, unarchive, update its text, its scope, then its
/// run state. Under DISABLEMENT a failed verify or text update fails the
/// rule, and the rule is disabled all the same; an archived rule is left as
/// it is.
async fn update(
    client: &Client<'_>,
    rule: &RuleDeploy,
    rule_id: &str,
    outcome: &mut RuleOutcome,
) -> Result<(), ConnectorError> {
    let disabling = rule.disabling;
    let read = async {
        let remote = client.get_rule(rule_id).await?;
        let deployment = client.get_deployment(rule_id).await?;
        Ok::<_, Failure>((remote, deployment))
    };
    let (remote, mut deployment) = match read.await {
        Ok(read) => read,
        Err(failure) => {
            let error = api(failure)?;
            if error.not_found() {
                return gone(client, rule, outcome).await;
            }
            outcome.request_failed(&error);
            return Ok(());
        }
    };
    health(&remote, &deployment, outcome);
    let archived = deployment.get("archived").is_some_and(Json::truthy);
    if disabling && archived {
        return Ok(());
    }
    let mut allowed: Vec<String> = match remote.get("allowedRunFrequencies") {
        Some(Json::Array(items)) => items.iter().map(opentide_compile::deploy::text).collect(),
        _ => Vec::new(),
    };
    let text = &rule.assembled.text;
    let changed = remote.get("text").and_then(Json::as_str) != Some(text.as_str());
    let mut text_ok = true;
    if changed {
        // Verify writes nothing: it comes before the unarchive, so a rule
        // that does not compile, or asks for a frequency Google refuses,
        // stays as it is.
        match verify(client, &rule.assembled, outcome).await? {
            Some(verified) => {
                if !verified.allowed.is_empty() {
                    allowed = verified.allowed;
                }
            }
            None if !disabling => return Ok(()),
            None => text_ok = false,
        }
    }
    if !disabling && !frequency_allowed(rule, &allowed, outcome) {
        return Ok(());
    }
    if archived {
        if let Err(failure) = client.set_archived(rule_id, false).await {
            outcome.deployment_failed(rule_id, &api(failure)?);
            return Ok(());
        }
        if let Json::Object(object) = &mut deployment {
            object.insert("archived".into(), Json::Bool(false));
        }
    }
    let mut tag = etag(&remote);
    if changed && text_ok {
        match client.update_text(rule_id, text, tag.as_deref()).await {
            Ok(patched) => tag = etag(&patched).or(tag),
            Err(failure) => {
                let error = api(failure)?;
                if error.not_found() {
                    return gone(client, rule, outcome).await;
                }
                outcome.write_failed(rule_id, &error);
                if !disabling {
                    return Ok(());
                }
            }
        }
    }
    let wanted = rule.scope.clone().unwrap_or_default();
    // Compared by scope id: Google may name the project by number where the
    // tenant names it by id, and a rule's scope is always in its own instance.
    let current = remote
        .get("scope")
        .filter(|value| value.truthy())
        .map(opentide_compile::deploy::text)
        .unwrap_or_default();
    if scope_id(&current) != scope_id(&wanted)
        && let Err(failure) = client.update_scope(rule_id, &wanted, tag.as_deref()).await
    {
        let error = api(failure)?;
        if error.not_found() {
            return gone(client, rule, outcome).await;
        }
        outcome.write_failed(rule_id, &error);
        if !disabling {
            return Ok(());
        }
    }
    let Some(update) = rule.run_state.changes(&deployment) else {
        return Ok(());
    };
    if let Err(failure) = client.update_deployment(rule_id, &update).await {
        outcome.deployment_failed(rule_id, &api(failure)?);
    }
    Ok(())
}

/// The bound rule no longer exists: create it again, or forget it when
/// retiring it.
async fn gone(
    client: &Client<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), ConnectorError> {
    if rule.retiring {
        outcome.warn(
            "google_secops_rule_missing",
            "the recorded rule no longer exists on the instance; its id is removed",
        );
        outcome.state = StateChange::Forget;
        return Ok(());
    }
    outcome.warn(
        "google_secops_rule_recreated",
        "the recorded rule no longer exists on the instance; creating it again",
    );
    if let Some((code, message)) = &rule.recreate_refusal {
        outcome.fail(code, message.clone());
        return Ok(());
    }
    create(client, rule, outcome).await
}

/// DELETION: archive the rule, or delete it without `force`.
async fn retire(
    client: &Client<'_>,
    rule: &RuleDeploy,
    rule_id: &str,
    outcome: &mut RuleOutcome,
) -> Result<(), ConnectorError> {
    if !rule.delete {
        return archive(client, rule_id, outcome).await;
    }
    if let Err(failure) = client.delete(rule_id).await {
        let error = api(failure)?;
        if error.refused_delete() {
            outcome.warn(
                "google_secops_delete_refused",
                format!(
                    "Google refused to delete rule {rule_id} (HTTP {} {}: {}); it is archived \
                     instead and keeps its binding",
                    error.http_status, error.status, error.message
                ),
            );
            return archive(client, rule_id, outcome).await;
        }
        if !error.not_found() {
            outcome.request_failed(&error);
            return Ok(());
        }
    }
    outcome.state = StateChange::Forget;
    Ok(())
}

async fn archive(
    client: &Client<'_>,
    rule_id: &str,
    outcome: &mut RuleOutcome,
) -> Result<(), ConnectorError> {
    let steps = async {
        let remote = client.get_deployment(rule_id).await?;
        if remote.get("archived").is_some_and(Json::truthy) {
            return Ok(());
        }
        let disabled = RunState::disabled();
        if disabled.differs_from(&remote) {
            client.update_deployment(rule_id, &disabled).await?;
        }
        client.set_archived(rule_id, true).await?;
        Ok::<(), Failure>(())
    };
    if let Err(failure) = steps.await {
        let error = api(failure)?;
        if error.not_found() {
            outcome.warn(
                "google_secops_rule_missing",
                "the recorded rule no longer exists on the instance; its id is removed",
            );
            outcome.state = StateChange::Forget;
        } else {
            outcome.request_failed(&error);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_end_a_resource_name() {
        let id = "ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1";
        let name = Json::Str(format!(" projects/p/locations/eu/instances/i/rules/{id} "));
        assert_eq!(returned_rule_id(Some(&name)).as_deref(), Some(id));
        assert_eq!(
            returned_rule_id(Some(&Json::Str(id.to_owned()))).as_deref(),
            Some(id)
        );
        assert_eq!(
            returned_rule_id(Some(&Json::Str(
                "rules/ru_CFC80C6B-f918-42ed-8d5c-9518c13586c1".to_owned()
            ))),
            None
        );
        assert_eq!(
            returned_rule_id(Some(&Json::Str("rules/ru_1".to_owned()))),
            None
        );
        assert_eq!(returned_rule_id(Some(&Json::Int(1))), None);
        assert_eq!(returned_rule_id(None), None);
    }
}
