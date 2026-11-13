//! Bitdefender GravityZone (bitdefender-1.0, Deploy): custom detection rules
//! through the Incidents API, JSON-RPC 2.0 at `<url>/v1.0/jsonrpc/incidents`.
//!
//! A port of 0.28.0's `platforms/bitdefender/client.py` and of `deployer.py`,
//! rule by rule and request for request:
//!
//! - Every request is a `POST` with a fresh string `id`. A personal API key
//!   is HTTP Basic (the key as user name), a service key the `X-API-Key`
//!   header. A response with an `error` member is a failure whatever its
//!   HTTP status.
//! - `-32001`, HTTP 401 and HTTP 403 refuse the whole tenant
//!   (`bitdefender_tenant_unauthorized`), and `-32601` says it has no
//!   Incidents API (`bitdefender_incidents_api_unavailable`, an on-premises
//!   console). `-32003` and HTTP 429 are waited out (`Retry-After`, else
//!   60 s) and the same request is sent again, because a rate-limited request
//!   was not executed: at most ten times.
//! - `createCustomRule` and `deleteCustomRule` are paced at most five per
//!   rolling minute per API key, across every tenant of the run that shares
//!   the key ([`Pacer`]). The pacer holds a per-process salted digest of the
//!   key ([`pace_key`]), never the key.
//! - No transport-level retry: a create that got no answer may have
//!   happened, so it is sent again once, never more, and a name conflict on
//!   that retry is `bitdefender_create_unconfirmed`.
//! - The GravityZone rule id is what deployment state records
//!   ([`StateChange`]): deploy never lists rules nor finds one by name. An
//!   update sends the whole payload; a rule the tenant lost (`-32002`) is
//!   created again, or forgotten when it was to be disabled. Exclusion rules
//!   (`type: 2`) are never created, updated or deleted: every call carries
//!   `type: 1` (`opentide-compile`'s params).
//!
//! The params are `opentide-compile`'s (`bitdefender::create_params`,
//! `update_params`, `delete_params`). GravityZone has no live validation and
//! no query runner here (`supported: False`).

use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher as _;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use opentide_compile::Json;
use opentide_compile::bitdefender::{
    CREATE, DELETE, GravityZoneRule, UPDATE, create_params, delete_params, update_params,
};
use opentide_compile::json::Object;

use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, Operation, Platform, TenantContext,
};
use crate::error::ConnectorError;
use crate::http::HttpSettings;
use crate::retry::{MAX_BACKOFF, RetryPolicy};

/// The platform's identifier.
pub const PLATFORM: &str = "bitdefender";

/// The Incidents API's JSON-RPC endpoint, under the tenant's `url`.
pub const API_PATH: &str = "/v1.0/jsonrpc/incidents";

/// The key is refused.
pub const UNAUTHORIZED: i64 = -32001;
/// The rule does not exist.
pub const NOT_FOUND: i64 = -32002;
/// Rate limited: the request was not executed.
pub const TOO_MANY_REQUESTS: i64 = -32003;
/// The method does not exist: no Incidents API.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// At most this many paced calls per [`PACE_WINDOW`] per API key.
pub const PACED_CALLS: usize = 5;
/// The pacing window.
pub const PACE_WINDOW: Duration = Duration::from_secs(60);
/// The methods paced per API key.
pub const PACED_METHODS: [&str; 2] = [CREATE, DELETE];
/// The wait when a rate limit names no `Retry-After`.
pub const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(60);
/// Rate-limited resends of one request before it fails.
pub const MAX_RATE_LIMITED: usize = 10;

/// `bitdefender_tenant_unauthorized`.
pub const TENANT_UNAUTHORIZED: &str = "bitdefender_tenant_unauthorized";
/// `bitdefender_incidents_api_unavailable`.
pub const INCIDENTS_API_UNAVAILABLE: &str = "bitdefender_incidents_api_unavailable";
/// `bitdefender_tenant_unreachable`.
pub const TENANT_UNREACHABLE: &str = "bitdefender_tenant_unreachable";
/// `bitdefender_request_failed`.
pub const REQUEST_FAILED: &str = "bitdefender_request_failed";
/// `bitdefender_name_conflict`.
pub const NAME_CONFLICT: &str = "bitdefender_name_conflict";
/// `bitdefender_create_unconfirmed`.
pub const CREATE_UNCONFIRMED: &str = "bitdefender_create_unconfirmed";
/// `bitdefender_create_no_id`.
pub const CREATE_NO_ID: &str = "bitdefender_create_no_id";
/// `bitdefender_kind_changed`.
pub const KIND_CHANGED: &str = "bitdefender_kind_changed";
/// `bitdefender_rule_missing`.
pub const RULE_MISSING: &str = "bitdefender_rule_missing";
/// `bitdefender_rule_recreated`.
pub const RULE_RECREATED: &str = "bitdefender_rule_recreated";
/// `bitdefender_actions_unsupported`.
pub const ACTIONS_UNSUPPORTED: &str = "bitdefender_actions_unsupported";
/// `bitdefender_create_retried`: the first create got no answer (a log
/// event, not a warning).
pub const CREATE_RETRIED: &str = "bitdefender_create_retried";

/// How a GravityZone tenant is reached: 30 s, and no transport retry (a
/// create that got no answer must not be sent again blindly).
pub fn http_defaults() -> HttpSettings {
    HttpSettings {
        timeout: Duration::from_secs(30),
        retry: RetryPolicy::none(),
        ..HttpSettings::default()
    }
}

/// A JSON-RPC call that failed for this rule only (`BitdefenderApiError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    /// The method.
    pub method: String,
    /// The JSON-RPC error code, when there was one.
    pub code: Option<i64>,
    /// What failed.
    pub message: String,
    /// `error.data.details`, when given.
    pub details: Option<String>,
}

impl ApiError {
    fn new(method: &str, code: Option<i64>, message: impl Into<String>) -> Self {
        Self {
            method: method.to_owned(),
            code,
            message: message.into(),
            details: None,
        }
    }

    /// The error and its details, as one text (`text`).
    pub fn text(&self) -> String {
        match &self.details {
            Some(details) if !details.is_empty() => format!("{self} {details}"),
            _ => self.to_string(),
        }
    }

    /// GravityZone refused a create because the name exists in the company
    /// (`name_conflict`).
    pub fn name_conflict(&self) -> bool {
        self.method == CREATE && is_name_conflict(self.details.as_deref())
    }

    /// GravityZone refused an update because the rule's kind differs
    /// (`type_mismatch`).
    pub fn type_mismatch(&self) -> bool {
        self.method == UPDATE && type_mismatch(&self.text())
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            Some(code) => write!(f, "{}: error {code}: {}", self.method, self.message)?,
            None => write!(f, "{}: {}", self.method, self.message)?,
        }
        if let Some(details) = self
            .details
            .as_deref()
            .filter(|details| !details.is_empty())
        {
            write!(f, " ({details})")?;
        }
        Ok(())
    }
}

fn pattern(
    cell: &'static OnceLock<Option<regex::Regex>>,
    text: &str,
) -> Option<&'static regex::Regex> {
    cell.get_or_init(|| regex::Regex::new(text).ok()).as_ref()
}

/// Whether a refusal's `error.data.details` says the rule name is already
/// taken (`is_name_conflict`). The spec maps `bitdefender_name_conflict` by
/// the details, not by the error code, which GravityZone shares with other
/// invalid parameters. The exact text is unconfirmed (RFC 0016, open
/// questions): this one pattern is what to tighten after a tenant check.
pub fn is_name_conflict(details: Option<&str>) -> bool {
    static NAME: OnceLock<Option<regex::Regex>> = OnceLock::new();
    static TAKEN: OnceLock<Option<regex::Regex>> = OnceLock::new();
    let text = details.unwrap_or_default();
    pattern(&NAME, r"(?i)\bnames?\b").is_some_and(|name| name.is_match(text))
        && pattern(
            &TAKEN,
            r"(?i)duplicat|already exists?|\bexists\b|taken|in use|unique",
        )
        .is_some_and(|taken| taken.is_match(text))
}

/// Whether an update's refusal says the rule's kind differs.
fn type_mismatch(text: &str) -> bool {
    static MISMATCH: OnceLock<Option<regex::Regex>> = OnceLock::new();
    pattern(
        &MISMATCH,
        r"(?i)\b(?:sub)?type\b[^.]*(?:mismatch|does not match|differ|cannot be changed)|(?:mismatch|cannot change)[^.]*\b(?:sub)?type\b",
    )
    .is_some_and(|mismatch| mismatch.is_match(text))
}

/// The 24-hex id a `createCustomRule` with `returnRuleId: true` answered
/// (`returned_rule_id`): the result itself, or its `ruleId` or `id`.
pub fn returned_rule_id(result: &Json) -> Option<String> {
    let value = match result {
        Json::Object(object) => object.get("ruleId").or_else(|| object.get("id"))?,
        other => other,
    };
    let id = value.as_str()?.trim().to_lowercase();
    (id.len() == 24 && id.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(id)
}

/// What sleeps and tells the time: the real clock in a run, a recorded one
/// in tests.
pub trait Clock: Send + Sync {
    /// Now, from the clock's own start.
    fn now(&self) -> Duration;

    /// Waits `duration`, or returns [`ConnectorError::Cancelled`] when the
    /// run is cancelled first.
    fn sleep<'a>(
        &'a self,
        duration: Duration,
        cancel: &'a tokio_util::sync::CancellationToken,
    ) -> BoxFuture<'a, Result<(), ConnectorError>>;
}

/// The process's clock.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed()
    }

    fn sleep<'a>(
        &'a self,
        duration: Duration,
        cancel: &'a tokio_util::sync::CancellationToken,
    ) -> BoxFuture<'a, Result<(), ConnectorError>> {
        Box::pin(async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => Ok(()),
                () = cancel.cancelled() => Err(ConnectorError::Cancelled),
            }
        })
    }
}

/// At most [`PACED_CALLS`] paced calls per rolling [`PACE_WINDOW`] per API
/// key (`_Pacer`). One pacer serves the whole process ([`pacer`]), so
/// tenants that share a key share its budget.
#[derive(Debug, Default)]
pub struct Pacer {
    calls: Mutex<HashMap<u64, VecDeque<Duration>>>,
}

impl Pacer {
    /// A pacer with no call made.
    pub fn new() -> Self {
        Self::default()
    }

    /// How long to wait before a call on `key` at `now`, or `None` (and the
    /// call counted) when it may go now.
    fn reserve(&self, key: u64, now: Duration) -> Option<Duration> {
        let mut calls = match self.calls.lock() {
            Ok(calls) => calls,
            Err(poisoned) => poisoned.into_inner(),
        };
        let made = calls.entry(key).or_default();
        while made
            .front()
            .is_some_and(|first| now.saturating_sub(*first) >= PACE_WINDOW)
        {
            made.pop_front();
        }
        if made.len() < PACED_CALLS {
            made.push_back(now);
            return None;
        }
        let first = made.front().copied().unwrap_or(now);
        Some(PACE_WINDOW.saturating_sub(now.saturating_sub(first)))
    }

    /// Waits until a call on `key` fits in the window, and counts it.
    pub async fn wait(
        &self,
        key: u64,
        clock: &dyn Clock,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<(), ConnectorError> {
        loop {
            match self.reserve(key, clock.now()) {
                None => return Ok(()),
                Some(pause) if pause.is_zero() => {}
                Some(pause) => clock.sleep(pause, cancel).await?,
            }
        }
    }
}

/// The pacer's key for `api_key`: a digest salted per process, so the
/// pacer never holds the key and its keys mean nothing outside the process
/// (`pace_key`).
pub fn pace_key(api_key: &str) -> u64 {
    static SALT: OnceLock<std::hash::RandomState> = OnceLock::new();
    SALT.get_or_init(std::hash::RandomState::new)
        .hash_one(api_key)
}

/// The process's pacer.
pub fn pacer() -> &'static Pacer {
    static PACER: OnceLock<Pacer> = OnceLock::new();
    PACER.get_or_init(Pacer::new)
}

/// How a call failed.
#[derive(Debug)]
pub enum CallError {
    /// This rule's call failed; the run goes on to the next rule.
    Api(ApiError),
    /// The call got no answer (a timeout, a reset, a truncated body): it may
    /// or may not have happened.
    NoAnswer(ConnectorError),
    /// The tenant refused the key, has no Incidents API, or the run was
    /// cancelled: no rule on it can deploy.
    Tenant(ConnectorError),
}

impl From<ApiError> for CallError {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

/// One tenant's client (`BitdefenderClient`).
pub struct Client<'a> {
    cx: TenantContext<'a>,
    pacer: &'a Pacer,
    clock: &'a dyn Clock,
}

impl std::fmt::Debug for Client<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("tenant", &self.cx.tenant.label)
            .finish_non_exhaustive()
    }
}

impl<'a> Client<'a> {
    /// The tenant's client, paced by `pacer` on `clock`.
    pub fn new(cx: TenantContext<'a>, pacer: &'a Pacer, clock: &'a dyn Clock) -> Self {
        Self { cx, pacer, clock }
    }

    fn tenant(&self) -> &str {
        &self.cx.tenant.label.tenant
    }

    fn refused(&self, code: &str, message: String) -> CallError {
        CallError::Tenant(ConnectorError::refused(
            PLATFORM,
            self.tenant(),
            format!("{code}: {message}"),
            None,
        ))
    }

    fn build(&self, body: &Json) -> Result<reqwest::Request, CallError> {
        let tenant = self.cx.tenant;
        let base = tenant
            .secret("url")
            .map_err(CallError::Tenant)?
            .expose()
            .trim_end_matches('/')
            .to_owned();
        let key = tenant.secret("api_key").map_err(CallError::Tenant)?;
        let service = tenant
            .secret("key_type")
            .is_ok_and(|kind| kind.expose() == "service");
        let bytes = serde_json::to_vec(body).map_err(|error| {
            CallError::Tenant(ConnectorError::Setup {
                platform: PLATFORM.to_owned(),
                tenant: self.tenant().to_owned(),
                message: error.to_string(),
            })
        })?;
        let mut builder = self
            .cx
            .http
            .request(reqwest::Method::POST, &format!("{base}{API_PATH}"))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(bytes);
        builder = if service {
            builder.header("X-API-Key", key.expose())
        } else {
            builder.basic_auth(key.expose(), Some(""))
        };
        builder.build().map_err(|error| {
            CallError::Tenant(ConnectorError::Setup {
                platform: PLATFORM.to_owned(),
                tenant: self.tenant().to_owned(),
                message: crate::error::describe(error),
            })
        })
    }

    async fn post(&self, body: &Json) -> Result<(u16, Duration, Vec<u8>), CallError> {
        let request = self.build(body)?;
        let classify = |error: ConnectorError| match error {
            ConnectorError::Cancelled => CallError::Tenant(error),
            other => CallError::NoAnswer(other),
        };
        let response = self
            .cx
            .http
            .send(request, self.cx.cancel)
            .await
            .map_err(classify)?;
        let status = response.status().as_u16();
        let retry_after = retry_after(
            response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
        );
        let bytes = self
            .cx
            .http
            .bytes(response, self.cx.cancel)
            .await
            .map_err(classify)?;
        Ok((status, retry_after, bytes))
    }

    /// Sends one JSON-RPC request and returns its `result` (`call`).
    pub async fn call(&self, method: &str, params: &Json) -> Result<Json, CallError> {
        let mut body = Object::new();
        body.insert("jsonrpc".into(), "2.0".into());
        body.insert("method".into(), method.into());
        body.insert("params".into(), params.clone());
        body.insert(
            "id".into(),
            uuid::Uuid::new_v4().simple().to_string().into(),
        );
        let body = Json::Object(body);
        let key = pace_key(
            self.cx
                .tenant
                .secret("api_key")
                .map_err(CallError::Tenant)?
                .expose(),
        );
        for _ in 0..=MAX_RATE_LIMITED {
            if PACED_METHODS.contains(&method) {
                self.pacer
                    .wait(key, self.clock, self.cx.cancel)
                    .await
                    .map_err(CallError::Tenant)?;
            }
            let (status, wait, bytes) = self.post(&body).await?;
            if matches!(status, 401 | 403) {
                return Err(self.refused(
                    TENANT_UNAUTHORIZED,
                    format!(
                        "tenant {} refused the API key: HTTP {status}",
                        self.tenant()
                    ),
                ));
            }
            if status == 429 {
                self.clock
                    .sleep(wait, self.cx.cancel)
                    .await
                    .map_err(CallError::Tenant)?;
                continue;
            }
            let Ok(payload) = serde_json::from_slice::<Json>(&bytes) else {
                return Err(ApiError::new(
                    method,
                    None,
                    format!("HTTP {status}: the answer is not JSON"),
                )
                .into());
            };
            if let Some(Json::Object(error)) = payload.get("error") {
                let code = match error.get("code") {
                    Some(Json::Int(code)) => Some(*code),
                    _ => None,
                };
                let message = error
                    .get("message")
                    .filter(|message| message.truthy())
                    .map(crate::python::python_str)
                    .unwrap_or_default();
                match code {
                    Some(TOO_MANY_REQUESTS) => {
                        self.clock
                            .sleep(wait, self.cx.cancel)
                            .await
                            .map_err(CallError::Tenant)?;
                        continue;
                    }
                    Some(UNAUTHORIZED) => {
                        return Err(self.refused(
                            TENANT_UNAUTHORIZED,
                            format!("tenant {} refused the API key: {message}", self.tenant()),
                        ));
                    }
                    Some(METHOD_NOT_FOUND) => {
                        return Err(self.refused(
                            INCIDENTS_API_UNAVAILABLE,
                            format!(
                                "tenant {} has no {method} (on-premises GravityZone has no \
                                 Incidents API)",
                                self.tenant()
                            ),
                        ));
                    }
                    _ => {
                        let mut failure = ApiError::new(method, code, message);
                        failure.details = details(error.get("data"));
                        return Err(failure.into());
                    }
                }
            }
            if status >= 300 {
                return Err(ApiError::new(method, None, format!("HTTP {status}")).into());
            }
            return match payload {
                Json::Object(mut object) if object.contains_key("result") => {
                    Ok(object.shift_remove("result").unwrap_or(Json::Null))
                }
                _ => Err(ApiError::new(method, None, "the answer has no result").into()),
            };
        }
        Err(ApiError::new(
            method,
            Some(TOO_MANY_REQUESTS),
            format!("still rate limited after {MAX_RATE_LIMITED} waits"),
        )
        .into())
    }
}

/// `Retry-After` in seconds, else [`DEFAULT_RETRY_AFTER`]; at most
/// [`MAX_BACKOFF`], as every connector waits out a `Retry-After`, so one
/// tenant cannot hold a run for an unbounded time.
fn retry_after(value: Option<&str>) -> Duration {
    let Some(seconds) = value.and_then(|value| value.trim().parse::<f64>().ok()) else {
        return DEFAULT_RETRY_AFTER;
    };
    if !seconds.is_finite() {
        return DEFAULT_RETRY_AFTER;
    }
    Duration::from_secs_f64(seconds.clamp(0.0, MAX_BACKOFF.as_secs_f64()))
}

/// `error.data.details`, or `error.data` when it is a string (`_details`).
fn details(data: Option<&Json>) -> Option<String> {
    match data? {
        Json::Object(data) => data
            .get("details")
            .filter(|details| !details.is_null())
            .map(crate::python::python_str),
        Json::Str(text) => Some(text.clone()),
        _ => None,
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
    /// What the block deploys on the tenant (`opentide-compile`'s
    /// `compile_rule`); unread for a delete.
    pub compiled: GravityZoneRule,
    /// Whether the block's status is a DISABLEMENT.
    pub disable: bool,
    /// Whether the block has actions the tenant cannot take (its
    /// `automatic_actions` is false): they are not sent.
    pub actions_unsupported: bool,
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

/// A warning a deploy raises (`DEPLOYMENT_WARNING_RAISED`), or a log event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// The event (`bitdefender_rule_recreated`).
    pub event: &'static str,
    /// What happened.
    pub detail: String,
    /// Whether it raises the run's warning (the create retry only logs).
    pub raised: bool,
}

/// Why a rule failed (`DEPLOYMENT_ERROR_RAISED`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// A request failed: its code (`bitdefender_request_failed`,
    /// `_name_conflict`, `_create_unconfirmed`, `_create_no_id`,
    /// `_kind_changed`), the error, and the request's own text.
    Request {
        /// The code.
        code: &'static str,
        /// What failed, for the reader.
        error: String,
        /// The request's error, when it adds to it.
        detail: Option<String>,
    },
    /// Deployment state refused the rule created again
    /// ([`RuleDeploy::recreate_refusal`]).
    Refused(String),
}

/// What a deploy of one rule did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleOutcome {
    /// The deployment-state change.
    pub state: StateChange,
    /// Warnings raised and events logged, in order.
    pub warnings: Vec<Warning>,
    /// The rule's failure.
    pub failure: Option<Failure>,
}

impl RuleOutcome {
    fn warn(&mut self, event: &'static str, detail: impl Into<String>) {
        self.warnings.push(Warning {
            event,
            detail: detail.into(),
            raised: true,
        });
    }

    fn fail(&mut self, code: &'static str, error: String, detail: Option<String>) {
        self.failure = Some(Failure::Request {
            code,
            error,
            detail,
        });
    }
}

/// A tenant error from a call: `bitdefender_tenant_unreachable` for a call
/// that got no answer, else the error itself.
fn tenant_error(error: CallError, tenant: &str) -> ConnectorError {
    match error {
        CallError::Tenant(error) => error,
        CallError::NoAnswer(error) => ConnectorError::refused(
            PLATFORM,
            tenant,
            format!("{TENANT_UNREACHABLE}: {}", error.text()),
            None,
        ),
        CallError::Api(error) => ConnectorError::refused(PLATFORM, tenant, error.text(), None),
    }
}

/// Deploys one rule (`BitdefenderDeploy.deploy_rule`) with the process's
/// pacer and clock. A rule's failure is in the outcome; an `Err` is the
/// tenant's (a refused key, no Incidents API, an unreachable tenant), which
/// stops the tenant.
pub async fn deploy_rule(
    cx: TenantContext<'_>,
    rule: &RuleDeploy,
) -> Result<RuleOutcome, ConnectorError> {
    deploy_rule_with(cx, rule, pacer(), &SystemClock).await
}

/// [`deploy_rule`] paced by `pacer` on `clock`.
pub async fn deploy_rule_with(
    cx: TenantContext<'_>,
    rule: &RuleDeploy,
    pacer: &Pacer,
    clock: &dyn Clock,
) -> Result<RuleOutcome, ConnectorError> {
    let client = Client::new(cx, pacer, clock);
    let mut outcome = RuleOutcome {
        state: StateChange::Keep,
        warnings: Vec::new(),
        failure: None,
    };
    let tenant = cx.tenant.label.tenant.clone();
    run(&client, rule, &mut outcome)
        .await
        .map_err(|error| tenant_error(error, &tenant))?;
    Ok(outcome)
}

async fn run(
    client: &Client<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), CallError> {
    let rule_id = match &rule.action {
        Action::Delete(rule_id) => {
            match client.call(DELETE, &delete_params(rule_id)).await {
                Ok(_) => {}
                Err(CallError::Api(error)) if error.code == Some(NOT_FOUND) => {}
                Err(CallError::Api(error)) => {
                    outcome.fail(REQUEST_FAILED, error.to_string(), None);
                    return Ok(());
                }
                Err(other) => return Err(other),
            }
            outcome.state = StateChange::Forget;
            return Ok(());
        }
        Action::Create => None,
        Action::Update(rule_id) => Some(rule_id),
    };
    if rule.actions_unsupported {
        outcome.warn(
            ACTIONS_UNSUPPORTED,
            "the tenant has no automatic actions; the block's actions are not sent",
        );
    }
    let Some(rule_id) = rule_id else {
        return create(client, rule, outcome).await;
    };
    match client
        .call(UPDATE, &update_params(&rule.compiled, rule_id))
        .await
    {
        Ok(_) => Ok(()),
        Err(CallError::Api(error)) if error.code == Some(NOT_FOUND) => {
            recreate(client, rule, outcome).await
        }
        Err(CallError::Api(error)) if error.type_mismatch() => {
            outcome.fail(
                KIND_CHANGED,
                format!(
                    "GravityZone rule {rule_id} is of another kind; changing the kind means \
                     DELETION, then a new deploy"
                ),
                Some(error.to_string()),
            );
            Ok(())
        }
        Err(CallError::Api(error)) => {
            outcome.fail(REQUEST_FAILED, error.to_string(), None);
            Ok(())
        }
        Err(other) => Err(other),
    }
}

async fn create(
    client: &Client<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), CallError> {
    let name = &rule.compiled.name;
    let params = create_params(&rule.compiled);
    let quoted = format!("{name:?}");
    let unconfirmed = format!(
        "the first create of {quoted} got no answer, so it may have succeeded with an id \
         opentide does not know. Resolve it in the GravityZone console (delete the rule, or \
         record its id in .opentide/states/deployment/)"
    );
    let result = match client.call(CREATE, &params).await {
        Ok(result) => result,
        Err(CallError::NoAnswer(first)) => {
            // No answer: the create may or may not have happened. Send it
            // once more, never more.
            outcome.warnings.push(Warning {
                event: CREATE_RETRIED,
                detail: first.text(),
                raised: false,
            });
            match client.call(CREATE, &params).await {
                Ok(result) => result,
                Err(CallError::NoAnswer(second)) => {
                    // Two creates may have landed: this rule only, the tenant goes on.
                    outcome.fail(
                        CREATE_UNCONFIRMED,
                        format!("{unconfirmed}; the retry got no answer either"),
                        Some(second.text()),
                    );
                    return Ok(());
                }
                Err(CallError::Api(error)) if error.name_conflict() => {
                    outcome.fail(
                        CREATE_UNCONFIRMED,
                        format!("{unconfirmed}; the retry found the name taken"),
                        Some(error.to_string()),
                    );
                    return Ok(());
                }
                Err(CallError::Api(error)) => {
                    outcome.fail(REQUEST_FAILED, error.to_string(), None);
                    return Ok(());
                }
                Err(other) => return Err(other),
            }
        }
        Err(CallError::Api(error)) if error.name_conflict() => {
            outcome.fail(
                NAME_CONFLICT,
                format!(
                    "a GravityZone rule named {quoted} already exists in the company; deploy \
                     does not adopt it. Rename the block (name) or remove the other rule"
                ),
                Some(error.to_string()),
            );
            return Ok(());
        }
        Err(CallError::Api(error)) => {
            outcome.fail(REQUEST_FAILED, error.to_string(), None);
            return Ok(());
        }
        Err(other) => return Err(other),
    };
    match returned_rule_id(&result) {
        Some(id) => outcome.state = StateChange::Record(id),
        None => outcome.fail(
            CREATE_NO_ID,
            format!(
                "createCustomRule for {quoted} answered {}, not a 24-hex rule id; the rule may \
                 exist on the tenant without a binding",
                result.to_compact()
            ),
            None,
        ),
    }
    Ok(())
}

/// The bound rule is gone (`-32002`): create it again, or forget it under a
/// DISABLEMENT (`_recreate`).
async fn recreate(
    client: &Client<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), CallError> {
    if rule.disable {
        outcome.warn(
            RULE_MISSING,
            "the recorded rule no longer exists on the tenant; its id is removed",
        );
        outcome.state = StateChange::Forget;
        return Ok(());
    }
    outcome.warn(
        RULE_RECREATED,
        "the recorded rule no longer exists on the tenant; creating it again",
    );
    if let Some(refusal) = &rule.recreate_refusal {
        outcome.failure = Some(Failure::Refused(refusal.clone()));
        return Ok(());
    }
    create(client, rule, outcome).await
}

/// The platform: a deployer. No live validator and no query runner.
#[derive(Debug, Default)]
pub struct Bitdefender;

impl Deployer for Bitdefender {
    /// One rule, from the compiled `createCustomRule` params alone (the
    /// [`DeployRequest`]'s body): created, updated (a [`Operation::Disable`]
    /// is an update of a body compiled under the DISABLEMENT), or deleted.
    /// A rule's failure is an error here too; [`deploy_rule`] takes the
    /// compiled rule.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        Box::pin(async move {
            let tenant = cx.tenant.label.tenant.clone();
            let compiled = compiled_from_create(&request.body).ok_or_else(|| {
                ConnectorError::refused(
                    PLATFORM,
                    &tenant,
                    "the request body is not createCustomRule params",
                    None,
                )
            })?;
            let rule = RuleDeploy {
                action: match request.operation {
                    Operation::Create => Action::Create,
                    Operation::Update | Operation::Disable => {
                        Action::Update(request.rule_id.clone())
                    }
                    Operation::Delete => Action::Delete(request.rule_id.clone()),
                },
                compiled,
                disable: request.operation == Operation::Disable,
                actions_unsupported: false,
                recreate_refusal: None,
            };
            let outcome = deploy_rule(cx, &rule).await?;
            match outcome.failure {
                Some(Failure::Request { code, error, .. }) => Err(ConnectorError::refused(
                    PLATFORM,
                    &tenant,
                    format!("{code}: {error}"),
                    None,
                )),
                Some(Failure::Refused(message)) => {
                    Err(ConnectorError::refused(PLATFORM, &tenant, message, None))
                }
                None => Ok(DeployOutcome {
                    remote_id: match outcome.state {
                        StateChange::Record(id) => Some(id),
                        StateChange::Keep => Some(request.rule_id.clone()),
                        StateChange::Forget => None,
                    },
                    operation: request.operation,
                }),
            }
        })
    }
}

/// A compiled rule read back from `createCustomRule` params (a
/// [`DeployRequest`]'s body); `None` when the body is not such params, or is
/// a whole JSON-RPC request carrying them.
pub fn compiled_from_create(body: &[u8]) -> Option<GravityZoneRule> {
    let body: Json = serde_json::from_slice(body).ok()?;
    let params = body.get("params").unwrap_or(&body);
    let kind = match params.get("subtype")? {
        Json::Int(1) => opentide_schema::objects::platform::bitdefender::Kind::Yara,
        Json::Int(0) => opentide_schema::objects::platform::bitdefender::Kind::Detection,
        _ => return None,
    };
    let text = |key: &str| params.get(key).and_then(Json::as_str).map(str::to_owned);
    Some(GravityZoneRule {
        uuid: String::new(),
        kind,
        name: text("name")?,
        description: text("description").unwrap_or_default(),
        tags: match params.get("tags") {
            Some(Json::Array(tags)) => tags
                .iter()
                .filter_map(|tag| tag.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        },
        settings: params.get("settings")?.as_object()?.clone(),
        targets: params.get("targets").cloned(),
        company_id: text("companyId"),
    })
}

impl Platform for Bitdefender {
    fn id(&self) -> &'static str {
        PLATFORM
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_conflict_is_read_from_the_details() {
        for details in [
            "A rule with this name already exists",
            "Duplicate rule name",
            "name is not unique",
            "The name is taken",
            "name already in use",
        ] {
            assert!(is_name_conflict(Some(details)), "{details}");
        }
        for details in ["Invalid params", "the name is too long", "already exists"] {
            assert!(!is_name_conflict(Some(details)), "{details}");
        }
        assert!(!is_name_conflict(None));
    }

    #[test]
    fn a_kind_change_is_read_from_the_error() {
        let mut error = ApiError::new(UPDATE, Some(-32602), "Invalid params");
        error.details = Some("The rule subtype cannot be changed".to_owned());
        assert!(error.type_mismatch());
        error.details = Some("type mismatch".to_owned());
        assert!(error.type_mismatch());
        error.details = Some("bad name".to_owned());
        assert!(!error.type_mismatch());
        error.method = CREATE.to_owned();
        error.details = Some("The rule subtype cannot be changed".to_owned());
        assert!(!error.type_mismatch());
    }

    #[test]
    fn errors_read_as_the_python_client_writes_them() {
        let mut error = ApiError::new(CREATE, Some(-32602), "Invalid params");
        assert_eq!(
            error.to_string(),
            "createCustomRule: error -32602: Invalid params"
        );
        error.details = Some("A rule with this name already exists".to_owned());
        assert_eq!(
            error.to_string(),
            "createCustomRule: error -32602: Invalid params (A rule with this name already exists)"
        );
        assert!(error.name_conflict());
        assert_eq!(
            ApiError::new(UPDATE, None, "HTTP 500").to_string(),
            "updateCustomRule: HTTP 500"
        );
    }

    #[test]
    fn the_returned_rule_id_is_24_hex() {
        let id = "6372b7a3897aaa77ee021642";
        assert_eq!(returned_rule_id(&Json::Str(id.into())).as_deref(), Some(id));
        assert_eq!(
            returned_rule_id(&Json::Str(format!(" {} ", id.to_uppercase()))).as_deref(),
            Some(id)
        );
        let mut object = Object::new();
        object.insert("ruleId".into(), id.into());
        assert_eq!(returned_rule_id(&Json::Object(object)).as_deref(), Some(id));
        assert_eq!(returned_rule_id(&Json::Bool(true)), None);
        assert_eq!(returned_rule_id(&Json::Str("6372b7".into())), None);
    }

    #[test]
    fn retry_after_is_seconds_else_a_minute() {
        assert_eq!(retry_after(Some("2")), Duration::from_secs(2));
        assert_eq!(retry_after(Some("0.5")), Duration::from_millis(500));
        assert_eq!(retry_after(Some("-3")), Duration::ZERO);
        assert_eq!(
            retry_after(Some("Wed, 21 Oct 2015 07:28:00 GMT")),
            DEFAULT_RETRY_AFTER
        );
        assert_eq!(retry_after(None), DEFAULT_RETRY_AFTER);
        assert_eq!(retry_after(Some("3600")), MAX_BACKOFF);
    }

    #[test]
    fn the_pacer_allows_five_calls_per_rolling_minute_per_key() {
        let pacer = Pacer::new();
        let at = Duration::from_secs;
        let (key, other) = (pace_key("k"), pace_key("other"));
        for second in 0..5 {
            assert_eq!(pacer.reserve(key, at(second)), None);
        }
        assert_eq!(pacer.reserve(key, at(10)), Some(at(50)));
        assert_eq!(pacer.reserve(other, at(10)), None);
        assert_eq!(pacer.reserve(key, at(60)), None);
        assert_eq!(pacer.reserve(key, at(60)), Some(at(1)));
    }

    #[test]
    fn the_pacer_never_holds_the_key() {
        assert_eq!(pace_key("secret"), pace_key("secret"));
        assert_ne!(pace_key("secret"), pace_key("other"));
        let pacer = Pacer::new();
        let _ = pacer.reserve(pace_key("secret"), Duration::ZERO);
        assert!(!format!("{pacer:?}").contains("secret"));
    }

    #[test]
    fn details_are_the_data_details_or_the_data() {
        let mut data = Object::new();
        data.insert("details".into(), "taken".into());
        assert_eq!(details(Some(&Json::Object(data))).as_deref(), Some("taken"));
        assert_eq!(
            details(Some(&Json::Str("text".into()))).as_deref(),
            Some("text")
        );
        assert_eq!(details(Some(&Json::Int(3))), None);
        assert_eq!(details(None), None);
    }
}
