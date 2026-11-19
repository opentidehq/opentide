//! Google Security Operations (google-secops-1.0, 0.28.0's platform rev 1.2):
//! YARA-L 2.0 detection rules through the Chronicle API v1.
//!
//! - [`auth`]: access tokens from a service-account key or Application
//!   Default Credentials, on the tenant's own client.
//! - [`client`]: one instance's requests, the bounded waits on 429 and 503.
//! - [`deploy`]: the rule lifecycle (`verifyRuleText`, create, bound-rule
//!   updates, run state, archive or delete).
//! - [`diagnostics`]: `verifyRuleText` answers put back on the block's
//!   section keys and lines.
//! - [`search`]: `udmSearch` results as rows.
//!
//! The text a rule deploys is `opentide-schema`'s assembled rule, built by
//! `opentide-compile`'s `google_secops` module with the requests.

pub mod auth;
pub mod client;
pub mod deploy;
pub mod diagnostics;
pub mod search;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use opentide_compile::Json;
use opentide_compile::google_secops::{default_endpoint, instance_resource};
use opentide_schema::objects::platform::google_secops::assemble::{AssembledRule, SectionPlace};
use opentide_schema::objects::platform::google_secops::yaral::SECTION_KEYS;

use crate::connector::{
    BoxFuture, DeployError, DeployEvent, DeployFailure, DeployOutcome, DeployRequest,
    DeployWarning, Deployer, LiveCheck, LiveValidator, Operation, Platform, QueryOutcome,
    QueryRequest, QueryRunner, TenantContext,
};
use crate::error::ConnectorError;
use crate::http::HttpSettings;
use crate::{Environment, TenantLabel};

use self::auth::{Authorizer, Clock};
use self::client::{Client, Failure};

/// The platform's identifier.
pub const PLATFORM: &str = "google_secops";

/// The live check's error code (`google_secops_compile_error`).
pub const COMPILE_ERROR: &str = "google_secops_compile_error";

/// The live check's warning code (`google_secops_compile_warning`).
pub const COMPILE_WARNING: &str = "google_secops_compile_warning";

/// A block `run_frequency` Google does not allow for the rule.
pub const FREQUENCY_NOT_ALLOWED: &str = "google_secops_run_frequency_not_allowed";

/// How an instance is reached: the caller's timeout (`for_tenant`'s), and no
/// transport-level retry (the client waits out 429 and 503 itself).
pub fn http_settings(timeout: std::time::Duration) -> HttpSettings {
    HttpSettings {
        timeout,
        ..HttpSettings::default()
    }
}

/// [`http_settings`] at the client's default, 60 s (deploy's).
pub fn http_defaults() -> HttpSettings {
    http_settings(client::DEFAULT_TIMEOUT)
}

/// Where a tenant's requests go: its endpoint and instance resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    /// `setup.endpoint`, else `https://{location}-chronicle.googleapis.com`.
    pub endpoint: String,
    /// `projects/{project}/locations/{location}/instances/{instance}`.
    pub resource: String,
}

impl Instance {
    /// The tenant's instance; a value still `$NAME` is refused.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::MissingCredential`] or [`ConnectorError::Setup`].
    pub fn of(tenant: &crate::Tenant) -> Result<Self, ConnectorError> {
        let project = tenant.secret("project")?.expose().to_owned();
        let location = tenant.secret("location")?.expose().to_owned();
        let instance = tenant.secret("instance")?.expose().to_owned();
        let endpoint = match tenant.setup.get("endpoint") {
            Some(_) => tenant.secret("endpoint")?.expose().to_owned(),
            None => default_endpoint(&location),
        };
        let endpoint = if endpoint.is_empty() {
            default_endpoint(&location)
        } else {
            endpoint
        };
        Ok(Self {
            endpoint,
            resource: instance_resource(&project, &location, &instance),
        })
    }

    /// The `scope` for the tenant's `data_access_scope`.
    pub fn scope(&self, tenant: &crate::Tenant) -> Option<String> {
        let scope = tenant
            .setup
            .get("data_access_scope")
            .and_then(crate::Credential::secret)
            .map(|secret| secret.expose().to_owned());
        opentide_compile::google_secops::scope_resource(&self.resource, scope.as_deref())
    }
}

/// The Google SecOps connector: the environment Application Default
/// Credentials are read from, the clock tokens are dated with, and each
/// tenant's credentials with its cached token.
pub struct GoogleSecops {
    env: Environment,
    clock: Clock,
    authorizers: Mutex<BTreeMap<TenantLabel, Arc<Authorizer>>>,
}

impl std::fmt::Debug for GoogleSecops {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleSecops").finish_non_exhaustive()
    }
}

impl GoogleSecops {
    /// A connector reading Application Default Credentials from `env`.
    pub fn new(env: Environment) -> Self {
        Self::with_clock(env, auth::system_clock())
    }

    /// A connector whose tokens are dated by `clock`.
    pub fn with_clock(env: Environment, clock: Clock) -> Self {
        Self {
            env,
            clock,
            authorizers: Mutex::new(BTreeMap::new()),
        }
    }

    /// The tenant's authorizer, its credentials loaded on first use.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Authentication`] (`google_secops_credentials_missing`)
    /// when the credentials are missing or cannot be read.
    pub fn authorizer(&self, tenant: &crate::Tenant) -> Result<Arc<Authorizer>, ConnectorError> {
        let mut authorizers = self
            .authorizers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(found) = authorizers.get(&tenant.label) {
            return Ok(Arc::clone(found));
        }
        let credentials = auth::load(tenant.setup.get("credentials"), &self.env)
            .map_err(|error| auth::credentials_missing(&tenant.label.tenant, &error))?;
        let authorizer = Arc::new(Authorizer::new(credentials, Arc::clone(&self.clock)));
        authorizers.insert(tenant.label.clone(), Arc::clone(&authorizer));
        Ok(authorizer)
    }
}

/// What the live check found for one rule (`RuleCheck`): its errors and
/// warnings, each with its code.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleCheck {
    /// Errors, each `<code>: <where>: <message>`.
    pub errors: Vec<String>,
    /// Warnings, each `google_secops_compile_warning: <where>: <message>`.
    pub warnings: Vec<String>,
}

/// The rule's assembled text compiled by `verifyRuleText` on one instance
/// (`validator.check_rule`): Google's `ERROR` diagnostics, then a
/// `run_frequency` Google does not allow, are errors; its `WARNING`
/// diagnostics are warnings, each placed on the section key and line it
/// falls in.
///
/// # Errors
///
/// The tenant's [`ConnectorError`]: refused credentials, an instance that
/// cannot be reached.
pub async fn check_rule(
    client: &Client<'_>,
    assembled: &AssembledRule,
    run_frequency: Option<&str>,
) -> Result<RuleCheck, ConnectorError> {
    let answer = match client.verify(&assembled.text).await {
        Ok(answer) => answer,
        Err(Failure::Tenant(error)) => return Err(error),
        Err(Failure::Api(error)) => {
            let status = if error.status.is_empty() {
                error.http_status.to_string()
            } else {
                error.status.clone()
            };
            return Ok(RuleCheck {
                errors: vec![format!(
                    "verifyRuleText failed: {status}: {}",
                    error.message
                )],
                warnings: Vec::new(),
            });
        }
    };
    let outcome = diagnostics::read_verify_answer(&answer);
    let mut errors: Vec<String> = outcome
        .errors
        .iter()
        .map(|item| {
            format!(
                "{COMPILE_ERROR}: {}",
                diagnostics::describe_diagnostic(item, assembled)
            )
        })
        .collect();
    if !outcome.success && errors.is_empty() {
        errors.push(format!(
            "{COMPILE_ERROR}: verifyRuleText did not report success"
        ));
    }
    if let Some(frequency) = run_frequency.filter(|frequency| !frequency.is_empty())
        && !outcome.allowed.is_empty()
        && !outcome.allowed.iter().any(|allowed| allowed == frequency)
    {
        errors.push(format!(
            "{FREQUENCY_NOT_ALLOWED}: configurations.google_secops.run_frequency {frequency} is \
             not one Google allows for this rule ({})",
            outcome.allowed.join(", ")
        ));
    }
    let warnings = outcome
        .warnings
        .iter()
        .map(|item| {
            format!(
                "{COMPILE_WARNING}: {}",
                diagnostics::describe_diagnostic(item, assembled)
            )
        })
        .collect();
    Ok(RuleCheck { errors, warnings })
}

impl LiveValidator for GoogleSecops {
    /// `request.text` as a whole YARA-L rule, compiled by `verifyRuleText`;
    /// its diagnostics carry Google's positions in that text. The CLI checks
    /// a rule's block with [`check_rule`] instead, which places them on the
    /// block's section keys.
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        Box::pin(async move {
            let instance = Instance::of(cx.tenant)?;
            let authorizer = self.authorizer(cx.tenant)?;
            let client = Client::new(cx, &authorizer, &instance.endpoint, &instance.resource);
            let assembled = AssembledRule {
                name: String::new(),
                text: request.text.clone(),
                sections: Vec::new(),
            };
            let check = check_rule(&client, &assembled, None).await?;
            if !check.errors.is_empty() {
                return Err(ConnectorError::refused(
                    PLATFORM,
                    &cx.tenant.label.tenant,
                    format!(
                        "Google SecOps tenant {} does not compile the rule",
                        cx.tenant.label.tenant
                    ),
                    Some(check.errors.join("; ")),
                ));
            }
            Ok(LiveCheck {
                result: None,
                errors: Vec::new(),
                warnings: check.warnings,
            })
        })
    }
}

impl QueryRunner for GoogleSecops {
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        Box::pin(async move {
            let instance = Instance::of(cx.tenant)?;
            let authorizer = self.authorizer(cx.tenant)?;
            let client = Client::new(cx, &authorizer, &instance.endpoint, &instance.resource);
            match client.udm_search(&search::params(request)).await {
                Ok(answer) => Ok(search::search_result(&answer, request.limit)),
                Err(Failure::Tenant(error)) => Err(error),
                Err(Failure::Api(error)) => {
                    let status = if error.status.is_empty() {
                        format!("HTTP {}", error.http_status)
                    } else {
                        error.status.clone()
                    };
                    Err(ConnectorError::refused(
                        PLATFORM,
                        &cx.tenant.label.tenant,
                        format!(
                            "Google SecOps refused the search on {} ({status})",
                            cx.tenant.label.tenant
                        ),
                        Some(error.message).filter(|message| !message.is_empty()),
                    ))
                }
            }
        })
    }
}

impl Deployer for GoogleSecops {
    /// The instance and the credentials, loaded, then the sign-in, once:
    /// the first rule's requests reuse the token.
    fn open<'a>(
        &'a self,
        cx: TenantContext<'a>,
    ) -> BoxFuture<'a, Result<(), crate::connector::DeployError>> {
        crate::connector::opening(async move {
            Instance::of(cx.tenant)?;
            // Signed in once: the first rule's requests reuse the token.
            self.authorizer(cx.tenant)?.token(cx).await.map(|_| ())
        })
    }

    /// One rule from its plan payload: the `rules.create` body's `text`,
    /// with the `name`, `sections`, `run_state` (`mask`, `body`) and
    /// `run_frequency` that `opentide deploy`'s plan compiles beside it
    /// (`opentide_compile::google_secops::compile_deployment`, the
    /// `deploy_plan` payload), so a PREVIEW rule deploys without alerting; a
    /// `run_state` that is not one fails the tenant's setup. A body with the
    /// text alone runs a create or an update under RELEASE. A
    /// [`Operation::Disable`] always disables. A
    /// [`Operation::Delete`] archives the rule, or deletes it under the
    /// tenant's `deletion = "delete"`. A rule's failure is an error here.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        Box::pin(async move {
            let tenant = cx.tenant.label.tenant.as_str();
            let body: Json = serde_json::from_slice(&request.body).unwrap_or(Json::Null);
            let instance = Instance::of(cx.tenant).map_err(tenant_failure)?;
            let authorizer = self.authorizer(cx.tenant).map_err(tenant_failure)?;
            let disabling = request.operation == Operation::Disable;
            // A disable disables, whatever state the payload was planned with.
            let run_state = if disabling {
                opentide_compile::google_secops::RunState::disabled()
            } else {
                match body.get("run_state") {
                    None => opentide_compile::google_secops::run_state(
                        &Json::Null,
                        opentide_compile::strategy::StatusStrategy::Release,
                    ),
                    Some(state) => {
                        planned_run_state(state).ok_or_else(|| ConnectorError::Setup {
                            platform: PLATFORM.to_owned(),
                            tenant: tenant.to_owned(),
                            message: "the payload's run_state is not {\"mask\": text, \"body\": \
                                      object}"
                                .to_owned(),
                        })?
                    }
                }
            };
            let rule = deploy::RuleDeploy {
                action: match request.operation {
                    Operation::Create => deploy::Action::Create,
                    Operation::Update | Operation::Disable => {
                        deploy::Action::Update(request.rule_id.clone())
                    }
                    Operation::Delete => deploy::Action::Delete(request.rule_id.clone()),
                },
                assembled: planned_rule(&body),
                run_state,
                run_frequency: body
                    .get("run_frequency")
                    .and_then(Json::as_str)
                    .map(str::to_owned),
                disabling,
                retiring: matches!(request.operation, Operation::Disable | Operation::Delete),
                scope: instance.scope(cx.tenant),
                delete: cx
                    .tenant
                    .setup
                    .get("deletion")
                    .and_then(crate::Credential::secret)
                    .is_some_and(|value| value.expose() == "delete"),
                recreate_refusal: request
                    .recreate_refusal
                    .as_ref()
                    .filter(|refusal| !refusal.message.is_empty())
                    .map(|refusal| (refusal.code, refusal.message.clone())),
            };
            let outcome = deploy::deploy_rule(
                cx,
                &authorizer,
                &instance.endpoint,
                &instance.resource,
                &rule,
            )
            .await
            .map_err(tenant_failure)?;
            outcome_of(outcome, request, tenant)
        })
    }
}

/// What the CLI's [`deploy::RuleOutcome`] is to a [`Deployer`]: the
/// outcome, or the rule's failures (the first, then [`DeployError::more`])
/// with what was done before them in [`DeployError::partial`].
fn outcome_of(
    outcome: deploy::RuleOutcome,
    request: &DeployRequest,
    tenant: &str,
) -> Result<DeployOutcome, DeployError> {
    let recorded = match &outcome.state {
        deploy::StateChange::Record(id) => Some(id.clone()),
        deploy::StateChange::Keep | deploy::StateChange::Forget => None,
    };
    let mut done = DeployOutcome::new(
        match &outcome.state {
            deploy::StateChange::Record(id) => Some(id.clone()),
            deploy::StateChange::Keep => Some(request.rule_id.clone()),
            deploy::StateChange::Forget => None,
        },
        request.operation,
    )
    .with_warnings(
        outcome
            .warnings
            .into_iter()
            .map(|warning| DeployWarning::new(warning.code, warning.detail))
            .collect(),
    )
    .with_events(
        recorded
            .iter()
            .map(|id| DeployEvent::new(RULE_CREATED).with_field("rule_id", id.as_str()))
            .collect(),
    );
    let mut failures = outcome.failures.into_iter().map(|failure| {
        DeployFailure::new(failure.code, failure.message)
            .with_field("platform", PLATFORM)
            .with_field("tenant", tenant)
    });
    let Some(first) = failures.next() else {
        return Ok(done);
    };
    // A failure keeps what was done before it: the id a create
    // recorded (its run state then refused), the warnings, the event.
    done.remote_id = recorded;
    Err(DeployError::rule(first)
        .with_more(failures)
        .with_partial(done))
}

/// The event a created rule's id is logged with.
pub const RULE_CREATED: &str = "google_secops_rule_created";

/// A tenant's failure (its instance, its credentials, an answer it did not
/// give): Google SecOps's code when the error names one
/// (`google_secops_credentials_missing`, `google_secops_tenant_unauthorized`),
/// else the connector error's own (`tenant_unreachable`, `tenant_timeout`,
/// `interrupted`, ...).
fn tenant_failure(error: ConnectorError) -> DeployError {
    let text = error.text();
    let named = text.split_once(": ").map(|(code, _)| code);
    let mut failed = DeployError::from(error);
    failed.scope = crate::connector::DeployScope::Tenant;
    match named {
        Some("google_secops_credentials_missing") => {
            failed.failure.code = "google_secops_credentials_missing";
        }
        Some("google_secops_tenant_unauthorized") => {
            failed.failure.code = "google_secops_tenant_unauthorized";
        }
        _ => {}
    }
    failed
}

/// The rule a plan payload carries: its `text`, its `name` (else the one
/// the text declares) and the `sections` written, each key one of
/// YARA-L's.
fn planned_rule(body: &Json) -> AssembledRule {
    let text = body
        .get("text")
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned();
    let name = body
        .get("name")
        .and_then(Json::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            text.strip_prefix("rule ")
                .and_then(|rest| rest.split_whitespace().next())
                .unwrap_or_default()
                .to_owned()
        });
    let count = |section: &Json, key: &str| {
        section
            .get(key)
            .and_then(|value| match value {
                Json::Int(count) => usize::try_from(*count).ok(),
                _ => None,
            })
            .unwrap_or_default()
    };
    let sections = match body.get("sections") {
        Some(Json::Array(sections)) => sections
            .iter()
            .filter_map(|section| {
                let key = section.get("key").and_then(Json::as_str)?;
                let key = SECTION_KEYS.into_iter().find(|known| *known == key)?;
                Some(SectionPlace {
                    key,
                    label_line: count(section, "label_line"),
                    lines: count(section, "lines"),
                    dropped: count(section, "dropped"),
                })
            })
            .collect(),
        _ => Vec::new(),
    };
    AssembledRule {
        name,
        text,
        sections,
    }
}

/// A plan payload's `run_state` (`mask`, `body`), or `None` when it is not
/// one.
fn planned_run_state(state: &Json) -> Option<opentide_compile::google_secops::RunState> {
    Some(opentide_compile::google_secops::RunState {
        mask: state.get("mask")?.as_str()?.to_owned(),
        body: state.get("body")?.as_object()?.clone(),
    })
}

impl Platform for GoogleSecops {
    fn id(&self) -> &'static str {
        PLATFORM
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self)
    }

    fn live_validator(&self) -> Option<&dyn LiveValidator> {
        Some(self)
    }

    fn query_runner(&self) -> Option<&dyn QueryRunner> {
        Some(self)
    }
}
