//! Sysdig Secure (UC-4.2, #832): custom Falco rules through the runtime API
//! (`/api/secure/rules`) and the runtime policies that name them
//! (`/api/v2/policies`), the endpoints Sysdig's own Terraform provider uses.
//!
//! A port of `platforms/sysdig/client.py` (`SysdigClient`: a bearer token,
//! 30 s, urllib3's retries; a 401 or 403 refuses the whole tenant) and of
//! `deployer.py`'s `deploy_api`, rule by rule and request for request:
//! create a rule and add it to the policies the block or the tenant names;
//! update it with the version the tenant holds, renaming it in those
//! policies; disable it (out of the policies) or delete it; create again a
//! recorded rule the tenant lost, or forget one that was to be disabled. The
//! rule id Sysdig gives is what deployment state records ([`StateChange`]).
//! Sysdig has no live validation and no query runner (`supported: False`).
//!
//! The body is `opentide-compile`'s (`sysdig::compile_body`): the Falco rule
//! with its block's macros and lists expanded into the condition, as Falco's
//! loader expands them.

use opentide_compile::Json;
use opentide_compile::json::Object;

use crate::answer::Answer;
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, Operation, Platform, TenantContext,
};
use crate::error::ConnectorError;
use crate::http::HttpSettings;
use crate::retry::RetryPolicy;

/// The platform's identifier.
pub const PLATFORM: &str = "sysdig";

/// Custom Falco rules.
const RULES: &str = "/api/secure/rules";
/// Runtime policies.
const POLICIES: &str = "/api/v2/policies";

/// How a Sysdig tenant is reached: 30 s, and urllib3's
/// `Retry(total=3, backoff_factor=0.5)` on 429 and 5xx for `GET`, `PUT`,
/// `DELETE` and `POST`.
pub fn http_defaults() -> HttpSettings {
    HttpSettings {
        timeout: std::time::Duration::from_secs(30),
        retry: RetryPolicy::urllib3(
            3,
            0.5,
            &[429, 500, 502, 503, 504],
            &["GET", "PUT", "DELETE", "POST"],
        ),
        ..HttpSettings::default()
    }
}

/// A request that failed for this rule only (`SysdigApiError`); a refused
/// token or a tenant that cannot be reached is a [`ConnectorError`] and
/// stops the tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    /// The answer's status, when there was one.
    pub status: Option<u16>,
    /// What failed, and the tenant's reason.
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// What failed: the rule ([`Failure::Rule`]) or the tenant.
#[derive(Debug)]
enum Failure {
    /// This rule's request failed; the run goes on to the next rule.
    Rule(ApiError),
    /// The tenant refused the token or could not be reached.
    Tenant(ConnectorError),
}

impl From<ConnectorError> for Failure {
    fn from(error: ConnectorError) -> Self {
        Self::Tenant(error)
    }
}

impl From<ApiError> for Failure {
    fn from(error: ApiError) -> Self {
        Self::Rule(error)
    }
}

/// Sysdig's error message from a body, else the raw text (`api_error`).
/// A message that is not a string is written as JSON.
fn api_error(answer: &Answer) -> String {
    if let Some(Json::Object(body)) = answer.json() {
        for key in ["message", "error", "errors"] {
            match body.get(key) {
                Some(Json::Str(text)) if !text.is_empty() => return text.clone(),
                Some(value) if value.truthy() => return value.to_compact(),
                _ => {}
            }
        }
    }
    answer.text()
}

fn http_failure(action: &str, answer: &Answer) -> ApiError {
    ApiError {
        status: Some(answer.status),
        message: format!("{action}: HTTP {}: {}", answer.status, api_error(answer)),
    }
}

/// One tenant's client (`SysdigClient`).
#[derive(Debug, Clone, Copy)]
pub struct Client<'a> {
    cx: TenantContext<'a>,
}

impl<'a> Client<'a> {
    /// The tenant's client; its `url` and `api_token` are read when sent.
    pub fn new(cx: TenantContext<'a>) -> Self {
        Self { cx }
    }

    fn tenant(&self) -> &str {
        &self.cx.tenant.label.tenant
    }

    /// Sends *method* to *path* with *body*; a 401 or 403 refuses the
    /// tenant (`_send`).
    async fn send(
        &self,
        method: crate::transport::Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Answer, ConnectorError> {
        let base = self
            .cx
            .tenant
            .secret("url")?
            .expose()
            .trim_end_matches('/')
            .to_owned();
        let token = self.cx.tenant.secret("api_token")?;
        let mut builder = self
            .cx
            .http
            .request(method, &format!("{base}{path}"))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", token.expose()));
        if let Some(body) = body {
            builder = builder.body(body);
        }
        let request = builder.build().map_err(|error| ConnectorError::Setup {
            platform: PLATFORM.to_owned(),
            tenant: self.tenant().to_owned(),
            message: error.describe(),
        })?;
        let answer = Answer::fetch(self.cx.http, request, self.cx.cancel).await?;
        if matches!(answer.status, 401 | 403) {
            return Err(ConnectorError::Refused {
                platform: PLATFORM.to_owned(),
                tenant: self.tenant().to_owned(),
                message: format!(
                    "Tenant {} refused the API token: HTTP {}: {}",
                    self.tenant(),
                    answer.status,
                    api_error(&answer)
                ),
                detail: None,
            });
        }
        Ok(answer)
    }

    /// The answer's JSON, or the rule's failure (`_json`).
    fn json(answer: &Answer, action: &str) -> Result<Json, ApiError> {
        if answer.status >= 300 {
            return Err(http_failure(action, answer));
        }
        answer.json().ok_or_else(|| http_failure(action, answer))
    }

    fn serialise(&self, value: &Json) -> Result<Vec<u8>, ConnectorError> {
        serde_json::to_vec(value).map_err(|error| ConnectorError::Setup {
            platform: PLATFORM.to_owned(),
            tenant: self.tenant().to_owned(),
            message: error.to_string(),
        })
    }

    /// Creates a rule from its *body* (`create_rule`).
    async fn create_rule(&self, body: &[u8]) -> Result<Result<Json, ApiError>, ConnectorError> {
        let answer = self
            .send(crate::transport::Method::POST, RULES, Some(body.to_vec()))
            .await?;
        Ok(Self::json(&answer, "create rule"))
    }

    /// The rule, or `None` when Sysdig no longer has it (`get_rule`).
    async fn get_rule(
        &self,
        rule_id: &str,
    ) -> Result<Result<Option<Json>, ApiError>, ConnectorError> {
        let answer = self
            .send(
                crate::transport::Method::GET,
                &format!("{RULES}/{rule_id}"),
                None,
            )
            .await?;
        if answer.status == 404 {
            return Ok(Ok(None));
        }
        Ok(Self::json(&answer, &format!("read rule {rule_id}")).map(Some))
    }

    /// Replaces the rule (`update_rule`).
    async fn update_rule(
        &self,
        rule_id: &str,
        body: &Json,
    ) -> Result<Result<Json, ApiError>, ConnectorError> {
        let bytes = self.serialise(body)?;
        let answer = self
            .send(
                crate::transport::Method::PUT,
                &format!("{RULES}/{rule_id}"),
                Some(bytes),
            )
            .await?;
        Ok(Self::json(&answer, &format!("update rule {rule_id}")))
    }

    /// Deletes the rule; one already gone (404) is not an error
    /// (`delete_rule`).
    async fn delete_rule(&self, rule_id: &str) -> Result<Result<(), ApiError>, ConnectorError> {
        let answer = self
            .send(
                crate::transport::Method::DELETE,
                &format!("{RULES}/{rule_id}"),
                None,
            )
            .await?;
        if answer.status != 404 && answer.status >= 300 {
            return Ok(Err(http_failure(
                &format!("delete rule {rule_id}"),
                &answer,
            )));
        }
        Ok(Ok(()))
    }

    /// The tenant's runtime policies (`list_policies`): a list, or one
    /// wrapped in `policies` or `data`.
    async fn list_policies(&self) -> Result<Result<Vec<Object>, ApiError>, ConnectorError> {
        let action = "list policies";
        let answer = self
            .send(crate::transport::Method::GET, POLICIES, None)
            .await?;
        let body = match Self::json(&answer, action) {
            Ok(body) => body,
            Err(error) => return Ok(Err(error)),
        };
        let list = match body {
            Json::Object(wrapper) => wrapper
                .get("policies")
                .or_else(|| wrapper.get("data"))
                .cloned()
                .unwrap_or(Json::Array(Vec::new())),
            other => other,
        };
        let Json::Array(items) = list else {
            return Ok(Err(ApiError {
                status: None,
                message: format!("{action}: the response is not a list of policies"),
            }));
        };
        Ok(Ok(items
            .into_iter()
            .filter_map(|item| match item {
                Json::Object(policy) => Some(policy),
                _ => None,
            })
            .collect()))
    }

    /// Replaces a policy (`update_policy`).
    async fn update_policy(
        &self,
        policy: &Object,
    ) -> Result<Result<Json, ApiError>, ConnectorError> {
        let name = policy
            .get("name")
            .map(opentide_compile::deploy::text)
            .unwrap_or_default();
        let action = format!("update policy '{name}'");
        let id = policy
            .get("id")
            .map(opentide_compile::deploy::text)
            .unwrap_or_default();
        let bytes = self.serialise(&Json::Object(policy.clone()))?;
        let answer = self
            .send(
                crate::transport::Method::PUT,
                &format!("{POLICIES}/{id}"),
                Some(bytes),
            )
            .await?;
        Ok(Self::json(&answer, &action))
    }
}

/// What a deploy does to the rule on the tenant (`ExternalIdAction`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// No id is recorded: create the rule.
    Create,
    /// The recorded id: update the rule (or disable it).
    Update(String),
    /// The recorded id, under a DELETION status: delete the rule.
    Delete(String),
}

/// One rule to deploy to one tenant.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleDeploy {
    /// What to do.
    pub action: Action,
    /// The body `opentide-compile` built (`api_body`), as bytes.
    pub body: Vec<u8>,
    /// The rule's name on Sysdig (`FalcoRule.name`).
    pub name: String,
    /// Whether the block tunes a rule Sysdig ships (`append`): a tuning
    /// joins no policy, and is deleted rather than disabled.
    pub tuning: bool,
    /// Whether the block's status is a DISABLEMENT.
    pub disable: bool,
    /// The policies the block names, else the tenant's (`policies`).
    pub policies: Vec<String>,
    /// Why deployment state cannot take a rule created again, when it
    /// cannot (`deployment_state_ignore`, `unpersisted_error`): a recorded
    /// rule the tenant lost is then not created again.
    pub recreate_refusal: Option<String>,
}

/// What deployment state makes of a deploy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateChange {
    /// Nothing changes.
    Keep,
    /// Record the id the tenant gave the rule (`record_created`).
    Record(String),
    /// Forget the rule's id (`record_deleted`).
    Forget,
}

/// A warning a deploy raises (`DEPLOYMENT_WARNING_RAISED`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// The event (`sysdig_rule_recreated`, `sysdig_rule_missing`).
    pub event: &'static str,
    /// What happened.
    pub detail: &'static str,
}

/// What a deploy of one rule did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleOutcome {
    /// The deployment-state change, made whether a later request failed
    /// or not (the create is recorded before the policies are joined).
    pub state: StateChange,
    /// Warnings raised.
    pub warnings: Vec<Warning>,
    /// The rule's failure (`sysdig_request_failed`, `DEPLOYMENT_ERROR_RAISED`).
    pub failure: Option<ApiError>,
}

/// Deploys one rule (`SysdigDeploy.deploy_api`). A rule's failure is in the
/// outcome; an `Err` is the tenant's (a refused token, an unreachable
/// tenant), which stops the tenant.
pub async fn deploy_rule(
    cx: TenantContext<'_>,
    rule: &RuleDeploy,
) -> Result<RuleOutcome, ConnectorError> {
    let client = Client::new(cx);
    let mut outcome = RuleOutcome {
        state: StateChange::Keep,
        warnings: Vec::new(),
        failure: None,
    };
    match run(&client, rule, &mut outcome).await {
        Ok(()) => Ok(outcome),
        Err(Failure::Rule(error)) => {
            outcome.failure = Some(error);
            Ok(outcome)
        }
        Err(Failure::Tenant(error)) => Err(error),
    }
}

/// The policies a rule joins: none for a tuning.
fn policies(rule: &RuleDeploy) -> &[String] {
    if rule.tuning { &[] } else { &rule.policies }
}

async fn run(
    client: &Client<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), Failure> {
    let policies = policies(rule);
    let rule_id = match &rule.action {
        Action::Delete(rule_id) => {
            if !policies.is_empty() {
                leave_policies(client, &rule.name, policies).await?;
            }
            client.delete_rule(rule_id).await??;
            outcome.state = StateChange::Forget;
            return Ok(());
        }
        Action::Create => return create(client, rule, outcome).await,
        Action::Update(rule_id) => rule_id,
    };
    let Some(remote) = client.get_rule(rule_id).await?? else {
        return recreate(client, rule, outcome).await;
    };
    if rule.disable && rule.tuning {
        // A tuning cannot be disabled: it is removed, with its binding.
        client.delete_rule(rule_id).await??;
        outcome.state = StateChange::Forget;
        return Ok(());
    }
    let mut body: Json = serde_json::from_slice(&rule.body).map_err(|error| ApiError {
        status: None,
        message: format!("update rule {rule_id}: the compiled body is not JSON: {error}"),
    })?;
    if let Json::Object(object) = &mut body {
        let id = remote.get("id").cloned().unwrap_or_else(|| {
            rule_id
                .parse::<i64>()
                .map_or_else(|_| Json::Str(rule_id.clone()), Json::Int)
        });
        object.insert("id".into(), id);
        if let Some(version) = remote.get("version") {
            object.insert("version".into(), version.clone());
        }
    }
    client.update_rule(rule_id, &body).await??;
    if let Some(Json::Str(old_name)) = remote.get("name")
        && !policies.is_empty()
        && *old_name != rule.name
    {
        rename_in_policies(client, old_name, &rule.name, policies).await?;
    }
    if rule.disable {
        leave_policies(client, &rule.name, policies).await
    } else {
        join_policies(client, &rule.name, policies).await
    }
}

async fn create(
    client: &Client<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), Failure> {
    let created = client.create_rule(&rule.body).await??;
    let Some(id) = created.get("id").filter(|id| !id.is_null()) else {
        return Err(Failure::Rule(ApiError {
            status: None,
            message: "create rule: the response carries no rule id".to_owned(),
        }));
    };
    outcome.state = StateChange::Record(opentide_compile::deploy::text(id));
    join_policies(client, &rule.name, policies(rule)).await
}

/// The recorded rule is gone from Sysdig (404): create it again, as a
/// create would; one to disable is forgotten (`_recreate`).
async fn recreate(
    client: &Client<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), Failure> {
    if rule.disable {
        outcome.warnings.push(Warning {
            event: "sysdig_rule_missing",
            detail: "the recorded rule no longer exists on the tenant; its id is removed",
        });
        outcome.state = StateChange::Forget;
        return Ok(());
    }
    outcome.warnings.push(Warning {
        event: "sysdig_rule_recreated",
        detail: "the recorded rule no longer exists on the tenant; creating it again",
    });
    if let Some(refusal) = &rule.recreate_refusal {
        return Err(Failure::Rule(ApiError {
            status: None,
            message: refusal.clone(),
        }));
    }
    create(client, rule, outcome).await
}

/// The named policies, or `sysdig_policy_missing` for those Sysdig lacks
/// (`_named`).
async fn named(client: &Client<'_>, names: &[String]) -> Result<Vec<Object>, Failure> {
    let listed = client.list_policies().await??;
    let by_name = |name: &str| {
        listed.iter().rev().find(|policy| {
            policy
                .get("name")
                .map(opentide_compile::deploy::text)
                .as_deref()
                == Some(name)
        })
    };
    let missing: Vec<String> = names
        .iter()
        .filter(|name| by_name(name).is_none())
        .map(|name| format!("'{name}'"))
        .collect();
    if !missing.is_empty() {
        return Err(Failure::Rule(ApiError {
            status: None,
            message: format!(
                "sysdig_policy_missing: no runtime policy named {} on tenant {}; create it in \
                 Sysdig Secure, or change the block's or the tenant's policies",
                missing.join(", "),
                client.tenant()
            ),
        }));
    }
    Ok(names
        .iter()
        .filter_map(|name| by_name(name).cloned())
        .collect())
}

/// A policy's rule names (`policy.get("ruleNames") or []`).
fn rule_names(policy: &Object) -> Vec<Json> {
    match policy.get("ruleNames") {
        Some(Json::Array(names)) => names.clone(),
        _ => Vec::new(),
    }
}

/// *policy* with *names* as its rule names, in their place.
fn with_rule_names(policy: &Object, names: Vec<Json>) -> Object {
    let mut updated = policy.clone();
    updated.insert("ruleNames".into(), Json::Array(names));
    updated
}

async fn join_policies(
    client: &Client<'_>,
    rule_name: &str,
    names: &[String],
) -> Result<(), Failure> {
    if names.is_empty() {
        return Ok(());
    }
    for policy in named(client, names).await? {
        let mut current = rule_names(&policy);
        if current.iter().any(|name| name.as_str() == Some(rule_name)) {
            continue;
        }
        current.push(rule_name.into());
        client
            .update_policy(&with_rule_names(&policy, current))
            .await??;
    }
    Ok(())
}

async fn leave_policies(
    client: &Client<'_>,
    rule_name: &str,
    names: &[String],
) -> Result<(), Failure> {
    if names.is_empty() {
        return Ok(());
    }
    for policy in named(client, names).await? {
        let current = rule_names(&policy);
        if !current.iter().any(|name| name.as_str() == Some(rule_name)) {
            continue;
        }
        let kept = current
            .into_iter()
            .filter(|name| name.as_str() != Some(rule_name))
            .collect();
        client
            .update_policy(&with_rule_names(&policy, kept))
            .await??;
    }
    Ok(())
}

async fn rename_in_policies(
    client: &Client<'_>,
    old: &str,
    new: &str,
    names: &[String],
) -> Result<(), Failure> {
    for policy in named(client, names).await? {
        let current = rule_names(&policy);
        if !current.iter().any(|name| name.as_str() == Some(old)) {
            continue;
        }
        let mut renamed: Vec<Json> = Vec::new();
        for name in current {
            let name = if name.as_str() == Some(old) {
                new.into()
            } else {
                name
            };
            if !renamed.contains(&name) {
                renamed.push(name);
            }
        }
        client
            .update_policy(&with_rule_names(&policy, renamed))
            .await??;
    }
    Ok(())
}

/// The platform: a deployer. No live validator and no query runner.
#[derive(Debug, Default)]
pub struct Sysdig;

impl Deployer for Sysdig {
    /// One rule, from the compiled body alone: its name and whether it is a
    /// tuning are read from the body (`name`, `details.append`), a
    /// [`Operation::Disable`] disables, and no runtime policy is joined or
    /// left; [`deploy_rule`] takes the block's or the tenant's policies.
    /// A rule's failure is an error here too.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        Box::pin(async move {
            let body: Option<Json> = serde_json::from_slice(&request.body).ok();
            let name = body
                .as_ref()
                .and_then(|body| body.get("name"))
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned();
            let tuning = body
                .as_ref()
                .and_then(|body| body.get("details"))
                .and_then(|details| details.get("append"))
                .is_some_and(Json::truthy);
            let action = match request.operation {
                Operation::Create => Action::Create,
                Operation::Update | Operation::Disable => Action::Update(request.rule_id.clone()),
                Operation::Delete => Action::Delete(request.rule_id.clone()),
            };
            let rule = RuleDeploy {
                action,
                body: request.body.clone(),
                name,
                tuning,
                disable: request.operation == Operation::Disable,
                policies: Vec::new(),
                recreate_refusal: None,
            };
            let outcome = deploy_rule(cx, &rule).await?;
            if let Some(failure) = outcome.failure {
                return Err(ConnectorError::Refused {
                    platform: PLATFORM.to_owned(),
                    tenant: cx.tenant.label.tenant.clone(),
                    message: failure.message,
                    detail: None,
                });
            }
            Ok(DeployOutcome {
                remote_id: match outcome.state {
                    StateChange::Record(id) => Some(id),
                    StateChange::Keep => Some(request.rule_id.clone()),
                    StateChange::Forget => None,
                },
                operation: request.operation,
            })
        })
    }
}

impl Platform for Sysdig {
    fn id(&self) -> &'static str {
        PLATFORM
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self)
    }
}
