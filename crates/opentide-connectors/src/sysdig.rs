//! Sysdig Secure (UC-4.2, #832): custom Falco rules through the runtime API
//! (`/api/secure/rules`) and the runtime policies that name them
//! (`/api/v2/policies`), the endpoints Sysdig's own Terraform provider uses.
//!
//! A port of `platforms/sysdig/client.py` (`SysdigClient`: a bearer token,
//! 30 s, the connectors' retries; a 401 or 403 refuses the whole tenant) and of
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
    BoxFuture, DeployError, DeployEvent, DeployFailure, DeployOutcome, DeployRequest, DeployScope,
    DeployWarning, Deployer, Operation, Platform, Prober, TenantContext,
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

/// How a Sysdig tenant is reached: 30 s, and the connectors' retries. Only
/// a read or a delete is sent again after a transient answer: a rule create
/// is a `POST`, and every update is a `PUT` that is never retried once
/// answered (`Client::send`): a rule's carries the `version` the tenant
/// held, and a policy is sent back as the tenant listed it.
pub fn http_defaults() -> HttpSettings {
    HttpSettings {
        timeout: std::time::Duration::from_secs(30),
        retry: RetryPolicy::standard(),
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
    if let Some(Json::Object(body)) = answer.quotable_json() {
        for key in ["message", "error", "errors"] {
            match body.get(key) {
                Some(Json::Str(text)) if !text.is_empty() => return text.clone(),
                Some(value) if value.is_filled() => return value.to_compact(),
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
        let answer = self.send_unclassified(method, path, body).await?;
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

    /// [`Self::send`] without its refusal of a 401 or 403: the answer as the
    /// tenant gave it, for the connectivity probe, which judges the status
    /// itself and quotes no body.
    async fn send_unclassified(
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
        let mut request = builder.build().map_err(|error| ConnectorError::Setup {
            platform: PLATFORM.to_owned(),
            tenant: self.tenant().to_owned(),
            message: error.describe(),
        })?;
        // A rule's `PUT` carries the `version` the tenant held (optimistic
        // concurrency): after the tenant applied a first copy, a second
        // names a stale version and fails. A policy's `PUT` sends back the
        // policy as the tenant listed it, a read-modify-write too. Neither
        // is sent again after an answer; one never sent still is.
        if request.method() == crate::transport::Method::PUT {
            request.set_idempotent(false);
        }
        Answer::fetch(self.cx.http, request, self.cx.cancel).await
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
        let name = policy.get("name").map(Json::to_text).unwrap_or_default();
        let action = format!("update policy '{name}'");
        let id = policy.get("id").map(Json::to_text).unwrap_or_default();
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
    outcome.state = StateChange::Record(Json::to_text(id));
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
        listed
            .iter()
            .rev()
            .find(|policy| policy.get("name").map(Json::to_text).as_deref() == Some(name))
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

/// The tenant's `url` and `api_token`: what [`Deployer::open`] and
/// [`Prober::probe`] resolve before they send anything.
fn resolve(cx: TenantContext<'_>) -> Result<(), ConnectorError> {
    cx.tenant.secret("url")?;
    cx.tenant.secret("api_token").map(|_| ())
}

impl Prober for Sysdig {
    /// The credentials resolved as a deploy resolves them (Sysdig has no
    /// sign-in), then one `GET /api/v2/policies`, the read a deploy makes
    /// to add a rule to its policies: it lists and changes nothing. A 401 or
    /// 403 is `authentication_failed`, as for every platform (a deploy's own
    /// refusal of the token keeps its message); no answer body is quoted.
    fn probe<'a>(&'a self, cx: TenantContext<'a>) -> BoxFuture<'a, Result<(), DeployError>> {
        crate::connector::probing(async move {
            resolve(cx)?;
            let answer = Client::new(cx)
                .send_unclassified(crate::transport::Method::GET, POLICIES, None)
                .await?;
            crate::connector::probe_verdict(
                PLATFORM,
                &cx.tenant.label.tenant,
                "reading the runtime policies",
                answer.status,
            )
        })
    }
}

impl Deployer for Sysdig {
    /// The tenant's `url` and `api_token`: nothing is sent.
    fn open<'a>(
        &'a self,
        cx: TenantContext<'a>,
    ) -> BoxFuture<'a, Result<(), crate::connector::DeployError>> {
        crate::connector::opening(async move { resolve(cx) })
    }

    /// One rule, from the compiled body alone: its name and whether it is a
    /// tuning are read from the body (`name`, `details.append`), a
    /// [`Operation::Disable`] disables, and the rule joins (or, disabled,
    /// leaves) the request's runtime policies ([`DeployRequest::policies`]:
    /// the block's), else the tenant's (its setup's `policies`), as
    /// `opentide deploy` chooses them. A recorded rule the tenant lost is
    /// created again and its new id returned, unless the request refuses it
    /// ([`DeployRequest::recreate_refusal`]). A delete sent without a body
    /// reads the rule's name from the tenant, to take it out of the
    /// policies. A created rule's id is the [`RULE_CREATED`] event.
    ///
    /// A rule Sysdig refuses fails with [`REQUEST_FAILED`] and its status,
    /// or the refusal's code; its [`DeployError::partial`] keeps the id of a
    /// rule created before the failure (its policies refused) and the
    /// warnings raised (`sysdig_rule_recreated` before a refused recreate).
    /// Refused credentials or an unreachable tenant fail the tenant.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        Box::pin(async move {
            let tenant = cx.tenant.label.tenant.as_str();
            let mut policies = request
                .policies
                .clone()
                .unwrap_or_else(|| cx.tenant.list("policies").to_vec());
            let mut body: Option<Json> = serde_json::from_slice(&request.body).ok();
            if request.operation == Operation::Delete
                && !policies.is_empty()
                && identity(body.as_ref()).0.is_empty()
            {
                body = Client::new(cx)
                    .get_rule(&request.rule_id)
                    .await
                    .map_err(tenant_failure)?
                    .map_err(|error| rule_failure(error, tenant))?;
            }
            let (name, tuning) = identity(body.as_ref());
            if name.is_empty() {
                // No name to find in a policy: the rule is in none of them.
                policies.clear();
            }
            let action = match request.operation {
                Operation::Create => Action::Create,
                Operation::Update | Operation::Disable => Action::Update(request.rule_id.clone()),
                Operation::Delete => Action::Delete(request.rule_id.clone()),
            };
            let refusal = request
                .recreate_refusal
                .as_ref()
                .filter(|refusal| !refusal.message.is_empty());
            let rule = RuleDeploy {
                action,
                body: request.body.clone(),
                name,
                tuning,
                disable: request.operation == Operation::Disable,
                policies,
                recreate_refusal: refusal.map(|refusal| refusal.message.clone()),
            };
            let outcome = deploy_rule(cx, &rule).await.map_err(tenant_failure)?;
            let recorded = match &outcome.state {
                StateChange::Record(id) => Some(id.clone()),
                StateChange::Keep | StateChange::Forget => None,
            };
            let done = DeployOutcome::new(
                match &outcome.state {
                    StateChange::Record(id) => Some(id.clone()),
                    StateChange::Keep => Some(request.rule_id.clone()),
                    StateChange::Forget => None,
                },
                request.operation,
            )
            .with_warnings(
                outcome
                    .warnings
                    .into_iter()
                    .map(|warning| DeployWarning::new(warning.event, warning.detail))
                    .collect(),
            )
            .with_events(
                recorded
                    .iter()
                    .map(|id| DeployEvent::new(RULE_CREATED).with_field("rule_id", id.as_str()))
                    .collect(),
            );
            let Some(failure) = outcome.failure else {
                return Ok(done);
            };
            let error = match refusal {
                Some(refusal) if refusal.message == failure.message => DeployError::rule(
                    refusal
                        .clone()
                        .with_field("platform", PLATFORM)
                        .with_field("tenant", tenant),
                ),
                _ => rule_failure(failure, tenant),
            };
            let mut partial = done;
            partial.remote_id = recorded;
            Err(error.with_partial(partial))
        })
    }
}

/// The event a created rule's id is logged with.
pub const RULE_CREATED: &str = "sysdig_rule_created";

/// The code of a rule Sysdig refused, or answered without what it needs.
pub const REQUEST_FAILED: &str = "sysdig_request_failed";

/// A tenant's failure from [`deploy_rule`]: refused credentials, an
/// unreachable tenant. Each of its rules would fail the same way.
fn tenant_failure(error: ConnectorError) -> DeployError {
    let mut failed = DeployError::from(error);
    failed.scope = DeployScope::Tenant;
    failed
}

/// A rule's failure ([`REQUEST_FAILED`]), with the status Sysdig answered.
fn rule_failure(error: ApiError, tenant: &str) -> DeployError {
    let mut failure = DeployFailure::new(REQUEST_FAILED, error.message)
        .with_field("platform", PLATFORM)
        .with_field("tenant", tenant);
    if let Some(status) = error.status {
        failure = failure.with_status(status);
    }
    DeployError::rule(failure)
}

/// A rule's name and whether it is a tuning, from its compiled body or the
/// tenant's copy (`name`, `details.append`): no name without one.
fn identity(rule: Option<&Json>) -> (String, bool) {
    let name = rule
        .and_then(|rule| rule.get("name"))
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned();
    let tuning = rule
        .and_then(|rule| rule.get("details"))
        .and_then(|details| details.get("append"))
        .is_some_and(Json::is_true);
    (name, tuning)
}

impl Platform for Sysdig {
    fn id(&self) -> &'static str {
        PLATFORM
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self)
    }

    fn prober(&self) -> Option<&dyn Prober> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_api_error_does_not_quote_the_bearer() {
        use crate::answer::{TEST_BEARER, answer_to_bearer};
        let answer = answer_to_bearer(&format!(r#"{{"message":"denied {TEST_BEARER}"}}"#));
        assert_eq!(api_error(&answer), "denied ***");
        let answer = answer_to_bearer(&format!(r#"{{"errors":["{TEST_BEARER}"]}}"#));
        assert_eq!(api_error(&answer), r#"["***"]"#);
    }
}
