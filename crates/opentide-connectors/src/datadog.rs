//! Datadog Cloud SIEM (RFC `docs/internal/rfc-datadog-cloud-siem.md` §8):
//! detection rules through the v2 Security Monitoring API, and searches
//! through Logs Search.
//!
//! One [`Session`] serves one tenant: every request carries the tenant's
//! `DD-API-KEY` and `DD-APPLICATION-KEY` and goes to `https://api.<site>`
//! (or the tenant's `api_url`). A `403`, or a `401` that is not a `PUT`'s,
//! stops the tenant (`datadog_tenant_unauthorized`); a `401` on a `PUT` is
//! Datadog's answer to a stale `version` (`datadog_concurrent_modification`).
//!
//! **Rate limits.** A `429` is waited out for the seconds its
//! `X-RateLimit-Reset` gives and the same request sent again, at most three
//! times ([`MAX_RATE_LIMITED`]): a `429` means Datadog did not take the
//! request, so even a create may be resent. A reset more than 120 seconds
//! away ([`MAX_RATE_LIMIT_WAIT`]) is not waited for. Either way the rule
//! fails `datadog_rate_limited`. No transport-level retry is mounted, so the
//! two never stack; a `GET` or a `DELETE` that got a gateway's `502`, `503`
//! or `504`, or that could not connect, is sent again on the shared policy's
//! waits ([`RetryPolicy::standard`]). A `POST` and a `PUT` (which carries the
//! `version`) are sent once; a create that got no answer, or a `5xx`, is not
//! resent (`datadog_create_unconfirmed`).
//!
//! **Deploy** (§8.2, §8.3). Every write is planned from deployment state:
//!
//! - no stored id: `POST /rules/validation`, then `POST /rules`, whose `id`
//!   is recorded;
//! - a stored id: `GET /rules/{id}`, then, only when a property opentide
//!   owns differs from the compiled body ([`differences`]), validation and a
//!   `PUT` with the `version` the `GET` returned; an unchanged rule is sent
//!   nothing (the shared `rule_unchanged` event);
//! - a DISABLEMENT is that same update, with `isEnabled: false`;
//! - a DELETION: `GET`, then `DELETE /rules/{id}`.
//!
//! A rule the `GET` finds gone (`404`, or `isDeleted: true`) is created again
//! (`datadog_rule_recreated`), or forgotten under a DISABLEMENT or a
//! DELETION (`datadog_rule_missing`). A default rule (`isDefault: true`) is
//! never changed (`datadog_rule_default`).
//!
//! The bodies are `opentide-compile`'s (`datadog::compile_rule`).

use std::sync::Arc;
use std::time::Duration;

use opentide_compile::Json;
use opentide_compile::datadog::{LOGS_SEARCH_PATH, RULES_PATH, VALIDATION_PATH, search_body};
use opentide_compile::json::Object;

use crate::Secret;
use crate::answer::Answer;
use crate::connector::{
    BoxFuture, DeployError, DeployEvent, DeployFailure, DeployOutcome, DeployRequest,
    DeployWarning, Deployer, LiveCheck, LiveValidator, Operation, Platform, Prober, QueryOutcome,
    QueryRequest, QueryRunner, Row, TenantContext, columns_of, flatten,
};
use crate::error::ConnectorError;
use crate::http::HttpSettings;
use crate::pace::{Clock, SystemClock};
use crate::retry::{Outcome, RetryPolicy};

/// The platform's identifier.
pub const PLATFORM: &str = "datadog";

/// Rate-limited resends of one request before it fails.
pub const MAX_RATE_LIMITED: u32 = 3;
/// The longest `X-RateLimit-Reset` waited for.
pub const MAX_RATE_LIMIT_WAIT: Duration = Duration::from_secs(120);
/// The wait when a `429` names no reset.
pub const DEFAULT_RATE_LIMIT_WAIT: Duration = Duration::from_secs(10);
/// The most events a search returns, over its pages.
pub const MAX_ROWS: usize = 10_000;

/// A `403`, or a `401` that is not a concurrent modification.
pub const UNAUTHORIZED: &str = "datadog_tenant_unauthorized";
/// DNS, TLS or a timeout.
pub const UNREACHABLE: &str = "datadog_tenant_unreachable";
/// A `site` outside the known list, with no `api_url`.
pub const SITE: &str = "datadog_site";
/// A `429` after the retries.
pub const RATE_LIMITED: &str = "datadog_rate_limited";
/// A `400` from validation or a write.
pub const RULE_INVALID: &str = "datadog_rule_invalid";
/// A create that got no answer, or a `5xx`; it is not resent.
pub const CREATE_UNCONFIRMED: &str = "datadog_create_unconfirmed";
/// A `401` on a `PUT`: the rule changed since the `GET`.
pub const CONCURRENT_MODIFICATION: &str = "datadog_concurrent_modification";
/// The stored id is gone (on DELETION or DISABLEMENT).
pub const RULE_MISSING: &str = "datadog_rule_missing";
/// The stored id was gone, and deploy created a new rule.
pub const RULE_RECREATED: &str = "datadog_rule_recreated";
/// The stored id is a default rule: opentide never changes one.
pub const RULE_DEFAULT: &str = "datadog_rule_default";
/// Any other answer Datadog gave a rule's request.
pub const REQUEST_FAILED: &str = "datadog_request_failed";

/// The properties of a rule opentide writes, and compares (RFC §8.2).
pub const OWNED: [&str; 9] = [
    "name",
    "isEnabled",
    "queries",
    "cases",
    "options",
    "message",
    "tags",
    "groupSignalsBy",
    "hasExtendedTitle",
];

/// The connect timeout and the read timeout of each request to the tenant;
/// with retries, a whole request can take longer.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How a Datadog tenant is reached: 30 s and no transport retries (the
/// session waits out rate limits itself, and a create is never sent twice).
pub fn http_defaults() -> HttpSettings {
    HttpSettings {
        timeout: REQUEST_TIMEOUT,
        ..HttpSettings::default()
    }
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

/// The tenant cannot take any request: a refused key, an unknown site, no
/// answer. It stops the tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantError {
    /// [`UNAUTHORIZED`], [`SITE`] or [`UNREACHABLE`].
    pub code: &'static str,
    /// What happened.
    pub message: String,
}

impl std::fmt::Display for TenantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// A request that failed for this rule or query only.
#[derive(Clone, Debug, PartialEq)]
pub struct ApiError {
    /// What was asked (`PUT /api/v2/security_monitoring/rules/<id>`).
    pub action: String,
    /// The HTTP status.
    pub status: u16,
    /// Datadog's reason.
    pub detail: String,
    /// Datadog's `errors[]`, each as text.
    pub errors: Vec<String>,
}

impl ApiError {
    fn new(action: impl Into<String>, status: u16, detail: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            status,
            detail: detail.into(),
            errors: Vec::new(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: HTTP {}: {}", self.action, self.status, self.detail)
    }
}

/// Why a call failed.
#[derive(Debug)]
pub enum Failure {
    /// This rule's or query's request failed.
    Api(ApiError),
    /// Datadog's rate limit held after the waits it allows.
    RateLimited(String),
    /// The tenant cannot take any request.
    Tenant(TenantError),
    /// The request got no answer (or the run was cancelled).
    NoAnswer(ConnectorError),
}

impl From<ApiError> for Failure {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

impl From<TenantError> for Failure {
    fn from(error: TenantError) -> Self {
        Self::Tenant(error)
    }
}

impl From<ConnectorError> for Failure {
    fn from(error: ConnectorError) -> Self {
        Self::NoAnswer(error)
    }
}

/// The [`ApiError`] a non-2xx answer reports, with Datadog's `errors[]`
/// (strings, or objects with a `detail` or `title`).
pub fn api_error(action: &str, answer: &Answer) -> ApiError {
    let mut error = ApiError::new(action, answer.status, "");
    if let Some(Json::Object(payload)) = answer.quotable_json()
        && let Some(Json::Array(entries)) = payload.get("errors")
    {
        error.errors = entries
            .iter()
            .map(|entry| match entry {
                Json::Object(fields) => ["detail", "title", "message"]
                    .iter()
                    .find_map(|key| fields.get(*key).filter(|value| value.is_filled()))
                    .map_or_else(|| entry.to_compact(), Json::to_text),
                other => Json::to_text(other),
            })
            .filter(|text| !text.trim().is_empty())
            .collect();
    }
    error.detail = if error.errors.is_empty() {
        answer
            .not_json_detail()
            .filter(|detail| !detail.is_empty())
            .or_else(|| Some(answer.text_head(500)).filter(|text| !text.is_empty()))
            .unwrap_or_else(|| reason(answer.status))
    } else {
        error.errors.join("; ")
    };
    error
}

/// The status's reason phrase.
fn reason(status: u16) -> String {
    crate::transport::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or_default()
        .to_owned()
}

/// An answer and the rate-limit header the client reads.
#[derive(Clone, Debug)]
pub struct Reply {
    /// The answer.
    pub answer: Answer,
    /// `X-RateLimit-Reset`: the seconds until the rate-limit window resets.
    pub reset: Option<String>,
}

/// The wait an `X-RateLimit-Reset` asks for: whole seconds, as Datadog's
/// rate-limits page documents; `None` when it is not a number.
pub fn rate_limit_reset(value: &str) -> Option<Duration> {
    let seconds: f64 = value.trim().parse().ok()?;
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    // A reset too large for a `Duration` is past any wait a deploy takes.
    Some(Duration::try_from_secs_f64(seconds).unwrap_or(Duration::MAX))
}

// ---------------------------------------------------------------------------
// The session.
// ---------------------------------------------------------------------------

/// A tenant's setup value, or `None` when it is unset or empty.
fn setting(cx: TenantContext<'_>, key: &str) -> Option<String> {
    cx.tenant
        .secret(key)
        .ok()
        .map(|value| value.expose().to_owned())
        .filter(|value| !value.is_empty())
}

/// The API base URL of a tenant: `api_url`, else `https://api.<site>`; a
/// site outside the known list with no `api_url` is [`SITE`].
pub fn base_url(cx: TenantContext<'_>) -> Result<String, TenantError> {
    let site = setting(cx, "site");
    let api_url = setting(cx, "api_url");
    opentide_schema::configuration::models::datadog_base_url(site.as_deref(), api_url.as_deref())
        .ok_or_else(|| TenantError {
            code: SITE,
            message: format!(
                "tenant {}: {} is not a Datadog site ({}); set site, or api_url for another site \
                 or a proxy",
                cx.tenant.label.tenant,
                site.map_or_else(
                    || "no site".to_owned(),
                    |site| opentide_schema::configuration::repr::quote(&site)
                ),
                opentide_schema::configuration::models::DATADOG_SITES.join(", ")
            ),
        })
}

/// One tenant's client.
pub struct Session<'a> {
    cx: TenantContext<'a>,
    base: String,
    api_key: Secret,
    application_key: Secret,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Session<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("tenant", &self.tenant())
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl<'a> Session<'a> {
    /// The tenant's session; waits on `clock`. An unset `$DD_API_KEY` is
    /// refused here, never sent.
    ///
    /// # Errors
    ///
    /// A [`Failure::NoAnswer`] holding the missing credential, or a
    /// [`Failure::Tenant`] for a site that is not one.
    pub fn new(cx: TenantContext<'a>, clock: Arc<dyn Clock>) -> Result<Self, Failure> {
        let api_key = cx.tenant.secret("api_key")?.clone();
        let application_key = cx.tenant.secret("app_key")?.clone();
        Ok(Self {
            cx,
            base: base_url(cx)?,
            api_key,
            application_key,
            clock,
        })
    }

    /// The tenant's name.
    pub fn tenant(&self) -> &str {
        &self.cx.tenant.label.tenant
    }

    /// The API base URL.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// One request, with `429`s waited out and a `GET`'s or `DELETE`'s
    /// transient failures retried. A `403` and a `401` (but a `PUT`'s) stop
    /// the tenant; every other answer is the caller's to judge.
    pub async fn request(
        &self,
        method: &crate::transport::Method,
        path: &str,
        body: Option<&Json>,
        timeout: Option<Duration>,
    ) -> Result<Reply, Failure> {
        let action = format!("{method} {path}");
        let url = format!("{}{path}", self.base);
        let bytes =
            body.map(serde_json::to_vec)
                .transpose()
                .map_err(|error| ConnectorError::Setup {
                    platform: PLATFORM.to_owned(),
                    tenant: self.tenant().to_owned(),
                    message: error.to_string(),
                })?;
        let retried_on_failure = matches!(
            *method,
            crate::transport::Method::GET | crate::transport::Method::DELETE
        );
        let standard = RetryPolicy::standard();
        let mut rate_limited = 0;
        let mut failed = 0;
        loop {
            let builder = self.builder(method, path, &url, bytes.as_deref(), timeout);
            let reply = match self.fetch(builder).await {
                Ok(reply) => reply,
                Err(error @ ConnectorError::Unreachable { .. }) if retried_on_failure => {
                    let Some(wait) =
                        standard.wait_for(true, Outcome::NotSent, failed, jiff::Timestamp::now())
                    else {
                        return Err(error.into());
                    };
                    self.clock.sleep(wait, self.cx.cancel).await?;
                    failed += 1;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let status = reply.answer.status;
            if status == 429 {
                let wait = reply
                    .reset
                    .as_deref()
                    .and_then(rate_limit_reset)
                    .unwrap_or(DEFAULT_RATE_LIMIT_WAIT);
                if wait > MAX_RATE_LIMIT_WAIT {
                    return Err(Failure::RateLimited(format!(
                        "{action}: Datadog's rate limit resets in {}s, more than the {}s a deploy \
                         waits",
                        wait.as_secs(),
                        MAX_RATE_LIMIT_WAIT.as_secs()
                    )));
                }
                if rate_limited >= MAX_RATE_LIMITED {
                    return Err(Failure::RateLimited(format!(
                        "{action}: still rate limited after {MAX_RATE_LIMITED} waits"
                    )));
                }
                self.clock.sleep(wait, self.cx.cancel).await?;
                rate_limited += 1;
                continue;
            }
            if retried_on_failure
                && matches!(status, 502..=504)
                && let Some(wait) = standard.wait_for(
                    true,
                    Outcome::Answer {
                        status: crate::transport::StatusCode::from_u16(status)
                            .unwrap_or(crate::transport::StatusCode::BAD_GATEWAY),
                        retry_after: None,
                    },
                    failed,
                    jiff::Timestamp::now(),
                )
            {
                self.clock.sleep(wait, self.cx.cancel).await?;
                failed += 1;
                continue;
            }
            let put = *method == crate::transport::Method::PUT;
            if status == 403 || (status == 401 && !put) {
                return Err(self.refused(&reply, &action).into());
            }
            return Ok(reply);
        }
    }

    /// One attempt's request: the keys, the body, and whether it writes.
    fn builder(
        &self,
        method: &crate::transport::Method,
        path: &str,
        url: &str,
        bytes: Option<&[u8]>,
        timeout: Option<Duration>,
    ) -> crate::transport::RequestBuilder {
        let mut builder = self
            .cx
            .http
            .request(method.clone(), url)
            .header("Accept", "application/json")
            .header("DD-API-KEY", self.api_key.expose())
            .header("DD-APPLICATION-KEY", self.application_key.expose());
        if let Some(bytes) = bytes {
            builder = builder
                .header("Content-Type", "application/json")
                .body(bytes.to_vec());
        }
        if path == LOGS_SEARCH_PATH
            || path == VALIDATION_PATH
            || *method == crate::transport::Method::GET
        {
            // A search, a validation and a read write no rule.
            builder = builder.read_only();
        }
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        builder
    }

    async fn fetch(
        &self,
        builder: crate::transport::RequestBuilder,
    ) -> Result<Reply, ConnectorError> {
        let request = builder.build().map_err(|error| ConnectorError::Setup {
            platform: PLATFORM.to_owned(),
            tenant: self.tenant().to_owned(),
            message: error.describe(),
        })?;
        let credentials = crate::answer::Credentials::of(&request);
        let started = std::time::Instant::now();
        let response = self.cx.http.send(request, self.cx.cancel).await?;
        let elapsed = started.elapsed();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let reset = header("x-ratelimit-reset");
        let content_type = header("content-type");
        let status = response.status().as_u16();
        let body = self.cx.http.bytes(response, self.cx.cancel).await?;
        Ok(Reply {
            answer: Answer::new(status, content_type, body, elapsed, &credentials),
            reset,
        })
    }

    fn refused(&self, reply: &Reply, what: &str) -> TenantError {
        let detail = api_error(what, &reply.answer).detail;
        let mut message = format!(
            "tenant {} refused {what}: HTTP {}",
            self.tenant(),
            reply.answer.status
        );
        if !detail.trim().is_empty() {
            message.push_str(&format!(" ({})", detail.trim()));
        }
        TenantError {
            code: UNAUTHORIZED,
            message,
        }
    }

    /// `GET /security_monitoring/rules/{id}`: the rule, or `None` when it is
    /// gone (`404`, or `isDeleted: true`).
    pub async fn get_rule(&self, rule_id: &str) -> Result<Option<Object>, Failure> {
        let path = format!("{RULES_PATH}/{rule_id}");
        let action = format!("GET {path}");
        let reply = self
            .request(&crate::transport::Method::GET, &path, None, None)
            .await?;
        if reply.answer.status == 404 {
            return Ok(None);
        }
        if reply.answer.status >= 300 {
            return Err(api_error(&action, &reply.answer).into());
        }
        match reply.answer.json() {
            Some(Json::Object(rule)) => {
                Ok((rule.get("isDeleted") != Some(&Json::Bool(true))).then_some(rule))
            }
            _ => Err(ApiError::new(action, reply.answer.status, "the answer is not a rule").into()),
        }
    }

    /// `POST /security_monitoring/rules/validation`: `Ok` when Datadog
    /// accepts the body (any 2xx), an [`ApiError`] with its `errors[]`
    /// otherwise.
    pub async fn validate_rule(&self, body: &Json) -> Result<(), Failure> {
        let action = format!("POST {VALIDATION_PATH}");
        let reply = self
            .request(
                &crate::transport::Method::POST,
                VALIDATION_PATH,
                Some(body),
                None,
            )
            .await?;
        if reply.answer.status >= 300 {
            return Err(api_error(&action, &reply.answer).into());
        }
        Ok(())
    }

    /// `POST /security_monitoring/rules`: the rule Datadog created.
    pub async fn create_rule(&self, body: &Json) -> Result<Object, Failure> {
        let action = format!("POST {RULES_PATH}");
        let reply = self
            .request(
                &crate::transport::Method::POST,
                RULES_PATH,
                Some(body),
                None,
            )
            .await?;
        if reply.answer.status >= 300 {
            return Err(api_error(&action, &reply.answer).into());
        }
        match reply.answer.json() {
            Some(Json::Object(rule)) => Ok(rule),
            _ => Err(ApiError::new(action, reply.answer.status, "the answer is not a rule").into()),
        }
    }

    /// `PUT /security_monitoring/rules/{id}`: the answer whatever its
    /// status (a `401` is a concurrent modification, not a refused key).
    pub async fn update_rule(&self, rule_id: &str, body: &Json) -> Result<Reply, Failure> {
        self.request(
            &crate::transport::Method::PUT,
            &format!("{RULES_PATH}/{rule_id}"),
            Some(body),
            None,
        )
        .await
    }

    /// `DELETE /security_monitoring/rules/{id}`: `true` when it deleted the
    /// rule, `false` when it was already gone (`404`).
    pub async fn delete_rule(&self, rule_id: &str) -> Result<bool, Failure> {
        let path = format!("{RULES_PATH}/{rule_id}");
        let reply = self
            .request(&crate::transport::Method::DELETE, &path, None, None)
            .await?;
        match reply.answer.status {
            404 => Ok(false),
            200..=299 => Ok(true),
            _ => Err(api_error(&format!("DELETE {path}"), &reply.answer).into()),
        }
    }

    /// `POST /logs/events/search`; the answer whatever its status.
    pub async fn search(&self, body: &Json, timeout: Option<Duration>) -> Result<Reply, Failure> {
        self.request(
            &crate::transport::Method::POST,
            LOGS_SEARCH_PATH,
            Some(body),
            timeout,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// The comparison (RFC §8.2).
// ---------------------------------------------------------------------------

/// Whether a value is what Datadog answers for a property left out: `false`,
/// an empty list, text or object, or null.
fn default_like(value: &Json) -> bool {
    match value {
        Json::Null | Json::Bool(false) | Json::Int(0) => true,
        Json::Float(number) => *number == 0.0,
        Json::Str(text) => text.is_empty(),
        Json::Array(items) => items.is_empty(),
        Json::Object(fields) => fields.is_empty(),
        _ => false,
    }
}

/// Whether two numbers, or two values, are the same.
fn same_scalar(ours: &Json, theirs: &Json) -> bool {
    match (ours, theirs) {
        (Json::Int(a), Json::Float(b)) | (Json::Float(b), Json::Int(a)) => {
            #[expect(
                clippy::cast_precision_loss,
                reason = "the API's numbers are small: windows, durations, tolerances"
            )]
            let a = *a as f64;
            (a - b).abs() < f64::EPSILON
        }
        (Json::Str(a), Json::Str(b)) => a.trim_end() == b.trim_end(),
        _ => ours == theirs,
    }
}

/// Whether the rule's value covers ours: an object's keys are ours (a key
/// we leave out is not compared, one Datadog leaves out equals our
/// default), a list's items are in order.
fn covers(ours: &Json, theirs: Option<&Json>) -> bool {
    let Some(theirs) = theirs.filter(|value| !value.is_null()) else {
        return default_like(ours);
    };
    match (ours, theirs) {
        (Json::Object(ours), Json::Object(theirs)) => ours
            .iter()
            .all(|(key, value)| covers(value, theirs.get(key))),
        (Json::Array(ours), Json::Array(theirs)) => {
            ours.len() == theirs.len()
                && ours
                    .iter()
                    .zip(theirs)
                    .all(|(ours, theirs)| covers(ours, Some(theirs)))
        }
        _ => same_scalar(ours, theirs),
    }
}

/// The tags of a value, as a set.
fn tag_set(value: Option<&Json>) -> std::collections::BTreeSet<String> {
    match value {
        Some(Json::Array(items)) => items.iter().map(Json::to_text).collect(),
        _ => std::collections::BTreeSet::new(),
    }
}

/// The compiled body with the defaults Datadog holds for what it leaves out
/// written in (RFC §8.2, "absent equals default"): every query's
/// `hasOptionalGroupByFields: false`, `groupSignalsBy: []`, and an
/// impossible travel rule's `detectIpTransition: false`. The comparison reads
/// it, so a value set on the tenant (a signal grouping, an optional group-by
/// field turned on in the UI) is a difference; the update sends it, so the
/// difference is cleared and the next deploy finds the rule unchanged.
pub fn with_defaults(compiled: &Json) -> Json {
    let Json::Object(fields) = compiled else {
        return compiled.clone();
    };
    let mut fields = fields.clone();
    if let Some(Json::Array(queries)) = fields.get_mut("queries") {
        for query in queries {
            if let Json::Object(query) = query {
                query
                    .entry("hasOptionalGroupByFields".to_owned())
                    .or_insert(Json::Bool(false));
            }
        }
    }
    if let Some(Json::Object(options)) = fields.get_mut("options")
        && let Some(Json::Object(travel)) = options.get_mut("impossibleTravelOptions")
    {
        travel
            .entry("detectIpTransition".to_owned())
            .or_insert(Json::Bool(false));
    }
    fields
        .entry("groupSignalsBy".to_owned())
        .or_insert_with(|| Json::Array(Vec::new()));
    Json::Object(fields)
}

/// The properties opentide owns ([`OWNED`]) whose value on the tenant's rule
/// differs from the compiled body, in [`OWNED`]'s order: empty when the rule
/// is unchanged. Tags are a set; queries and cases keep their order; a
/// property the body leaves out equals Datadog's default, and what the
/// answer adds (`id`, `version`, `defaultTags`, …) is not compared.
pub fn differences(compiled: &Json, stored: &Object) -> Vec<&'static str> {
    let compiled = &with_defaults(compiled);
    OWNED
        .iter()
        .copied()
        .filter(|key| {
            let ours = compiled.get(key);
            let theirs = stored.get(*key);
            if *key == "tags" {
                return tag_set(ours) != tag_set(theirs);
            }
            match ours {
                Some(ours) => !covers(ours, theirs),
                None => theirs.is_some_and(|theirs| !default_like(theirs)),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Deploy.
// ---------------------------------------------------------------------------

/// What a deploy does to the rule on the tenant.
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
    /// The compiled body (`compile_rule`).
    pub body: Json,
    /// Whether the block's status is a DISABLEMENT.
    pub disable: bool,
    /// Why deployment state cannot take a rule created again, when it cannot
    /// (`deployment_state_unpersisted`): the code and the message. A recorded
    /// rule the tenant lost is then not created again.
    pub recreate_refusal: Option<(&'static str, String)>,
}

/// What deployment state makes of a deploy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateChange {
    /// Nothing changes.
    Keep,
    /// Record the id the tenant gave the rule.
    Record(String),
    /// Forget the rule's id.
    Forget,
}

/// A warning or an error a deploy raises, with its log fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// The code (`datadog_rule_invalid`).
    pub code: &'static str,
    /// What happened.
    pub message: String,
    /// More fields of the log line (`errors`, `detail`, `changed`).
    pub fields: Vec<(&'static str, String)>,
}

impl Event {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            fields: Vec::new(),
        }
    }

    fn with(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.fields.push((key, value.into()));
        self
    }
}

/// What a deploy of one rule did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleOutcome {
    /// The deployment-state change.
    pub state: StateChange,
    /// What was done (`datadog_rule_created`, `_updated`, `_disabled`,
    /// `_deleted`, or `rule_unchanged`), with the rule id, and the properties an
    /// update changed.
    pub done: Option<(&'static str, String)>,
    /// The properties an update sent because they differed.
    pub changed: Vec<&'static str>,
    /// The calls made, in order (`GET`, `POST validation`, `PUT`, …), for the
    /// tests and the log.
    pub calls: Vec<&'static str>,
    /// Warnings raised.
    pub warnings: Vec<Event>,
    /// The rule's failure.
    pub failure: Option<Event>,
}

impl RuleOutcome {
    fn new() -> Self {
        Self {
            state: StateChange::Keep,
            done: None,
            changed: Vec::new(),
            calls: Vec::new(),
            warnings: Vec::new(),
            failure: None,
        }
    }
}

/// A failure that stops the tenant: its code and its text.
#[derive(Debug)]
pub struct TenantFailure {
    /// [`UNAUTHORIZED`], [`SITE`] or [`UNREACHABLE`].
    pub code: &'static str,
    /// The error, as the log line's `error`.
    pub message: String,
    /// The connector's error, when the tenant did not answer.
    pub error: Option<Box<ConnectorError>>,
}

impl TenantFailure {
    fn of(failure: Failure) -> Self {
        match failure {
            Failure::Tenant(error) => Self {
                code: error.code,
                message: error.to_string(),
                error: None,
            },
            Failure::Api(error) => Self {
                code: UNREACHABLE,
                message: error.to_string(),
                error: None,
            },
            Failure::RateLimited(message) => Self {
                code: RATE_LIMITED,
                message,
                error: None,
            },
            Failure::NoAnswer(error) => Self {
                code: UNREACHABLE,
                message: error.text(),
                error: Some(Box::new(error)),
            },
        }
    }

    /// The connector's error for this failure.
    pub fn into_error(self, tenant: &str) -> ConnectorError {
        match self.error {
            Some(error) => *error,
            None => ConnectorError::refused(PLATFORM, tenant, self.message, None),
        }
    }
}

/// The failure of a rule's request Datadog answered: a `400` is
/// [`RULE_INVALID`] with Datadog's `errors[]`.
fn failed(error: &ApiError) -> Event {
    if error.status == 400 {
        let mut event = Event::new(RULE_INVALID, error.to_string());
        if !error.errors.is_empty() {
            event = event.with(
                "errors",
                Json::Array(error.errors.iter().cloned().map(Json::Str).collect()).to_compact(),
            );
        }
        event
    } else {
        Event::new(REQUEST_FAILED, error.to_string())
    }
}

/// A rule's failure from a call: Datadog's answer or its rate limit fail the
/// rule (`Ok(Some)`); anything else stops the tenant (`Err`).
fn rule_failure(failure: Failure) -> Result<Event, Failure> {
    match failure {
        Failure::Api(error) => Ok(failed(&error)),
        Failure::RateLimited(message) => Ok(Event::new(RATE_LIMITED, message)),
        other => Err(other),
    }
}

/// Deploys one rule. A rule's failure is in the outcome; an `Err` stops the
/// tenant: a refused key, no answer to a request other than a create.
pub async fn deploy_rule(
    session: &Session<'_>,
    rule: &RuleDeploy,
) -> Result<RuleOutcome, TenantFailure> {
    let mut outcome = RuleOutcome::new();
    match run(session, rule, &mut outcome).await {
        Ok(()) => Ok(outcome),
        Err(failure) => Err(TenantFailure::of(failure)),
    }
}

async fn run(
    session: &Session<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), Failure> {
    let rule_id = match &rule.action {
        Action::Create => return create(session, rule, outcome).await,
        Action::Update(rule_id) | Action::Delete(rule_id) => rule_id,
    };
    outcome.calls.push("GET");
    let stored = match session.get_rule(rule_id).await {
        Ok(stored) => stored,
        Err(failure) => {
            outcome.failure = Some(rule_failure(failure)?);
            return Ok(());
        }
    };
    let Some(stored) = stored else {
        return gone(session, rule, rule_id, outcome).await;
    };
    if stored.get("isDefault") == Some(&Json::Bool(true)) {
        outcome.failure = Some(Event::new(
            RULE_DEFAULT,
            format!(
                "Datadog rule {rule_id} is a default rule, which opentide never changes or \
                 deletes: remove its id from .opentide/states/deployment/"
            ),
        ));
        return Ok(());
    }
    if matches!(rule.action, Action::Delete(_)) {
        outcome.calls.push("DELETE");
        match session.delete_rule(rule_id).await {
            Ok(true) => outcome.done = Some(("datadog_rule_deleted", rule_id.clone())),
            Ok(false) => outcome.warnings.push(missing(rule_id)),
            Err(failure) => {
                outcome.failure = Some(rule_failure(failure)?);
                return Ok(());
            }
        }
        outcome.state = StateChange::Forget;
        return Ok(());
    }
    let version = stored.get("version").cloned().unwrap_or(Json::Null);
    let body = if rule.disable {
        // A DISABLEMENT turns the rule off and nothing else (RFC §8.2): it is
        // neither compared nor validated, so a rule whose content Datadog
        // would now refuse is still disabled.
        if stored.get("isEnabled") == Some(&Json::Bool(false)) {
            outcome.done = Some((crate::connector::RULE_UNCHANGED, rule_id.clone()));
            return Ok(());
        }
        outcome.changed = vec!["isEnabled"];
        let mut body = Object::new();
        body.insert("isEnabled".into(), Json::Bool(false));
        body.insert("version".into(), version);
        body
    } else {
        let changed = differences(&rule.body, &stored);
        if changed.is_empty() {
            outcome.done = Some((crate::connector::RULE_UNCHANGED, rule_id.clone()));
            return Ok(());
        }
        outcome.changed = changed;
        outcome.calls.push("POST validation");
        if let Err(failure) = session.validate_rule(&rule.body).await {
            outcome.failure = Some(rule_failure(failure)?);
            return Ok(());
        }
        update_body(&rule.body, version)
    };
    outcome.calls.push("PUT");
    let reply = match session.update_rule(rule_id, &Json::Object(body)).await {
        Ok(reply) => reply,
        Err(failure) => {
            outcome.failure = Some(rule_failure(failure)?);
            return Ok(());
        }
    };
    if reply.answer.status == 404 {
        return gone(session, rule, rule_id, outcome).await;
    }
    put_answered(&reply, rule, rule_id, outcome);
    Ok(())
}

/// What the `PUT`'s answer makes of the rule: updated (or disabled), a
/// concurrent modification (`401`), or Datadog's refusal.
fn put_answered(reply: &Reply, rule: &RuleDeploy, rule_id: &str, outcome: &mut RuleOutcome) {
    let action = format!("PUT {RULES_PATH}/{rule_id}");
    match reply.answer.status {
        200..=299 => {
            outcome.done = Some((
                if rule.disable {
                    "datadog_rule_disabled"
                } else {
                    "datadog_rule_updated"
                },
                rule_id.to_owned(),
            ));
        }
        401 => {
            outcome.failure = Some(
                Event::new(
                    CONCURRENT_MODIFICATION,
                    format!(
                        "Datadog rule {rule_id} changed after deploy read it (HTTP 401 on the \
                         update, which carries the version read): run the deploy again"
                    ),
                )
                .with("detail", api_error(&action, &reply.answer).detail),
            );
        }
        _ => outcome.failure = Some(failed(&api_error(&action, &reply.answer))),
    }
}

/// The `PUT` body (`SecurityMonitoringRuleUpdatePayload`): the compiled body
/// with Datadog's defaults written in ([`with_defaults`]), without `type`,
/// which the update does not take, and with the `version` the `GET` read.
pub fn update_body(compiled: &Json, version: Json) -> Object {
    let mut body = match with_defaults(compiled) {
        Json::Object(fields) => fields,
        _ => Object::new(),
    };
    body.shift_remove("type");
    body.insert("version".into(), version);
    body
}

fn missing(rule_id: &str) -> Event {
    Event::new(
        RULE_MISSING,
        format!("Datadog rule {rule_id} no longer exists on the tenant; its id is removed"),
    )
}

/// The recorded rule is gone: forget it under a DELETION or a DISABLEMENT,
/// else create it again, unless deployment state cannot keep the new id.
async fn gone(
    session: &Session<'_>,
    rule: &RuleDeploy,
    rule_id: &str,
    outcome: &mut RuleOutcome,
) -> Result<(), Failure> {
    if rule.disable || matches!(rule.action, Action::Delete(_)) {
        outcome.warnings.push(missing(rule_id));
        outcome.state = StateChange::Forget;
        return Ok(());
    }
    outcome.warnings.push(Event::new(
        RULE_RECREATED,
        format!("Datadog rule {rule_id} no longer exists on the tenant; creating it again"),
    ));
    if let Some((code, message)) = &rule.recreate_refusal {
        outcome.failure = Some(Event::new(code, message.clone()));
        return Ok(());
    }
    create(session, rule, outcome).await
}

/// Validation, then the create; the id Datadog answers is recorded.
async fn create(
    session: &Session<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), Failure> {
    outcome.calls.push("POST validation");
    if let Err(failure) = session.validate_rule(&rule.body).await {
        outcome.failure = Some(rule_failure(failure)?);
        return Ok(());
    }
    let name = rule.body.get("name").map(Json::to_text).unwrap_or_default();
    let quoted = opentide_schema::configuration::repr::quote(&name);
    let unconfirmed = |how: &str| {
        format!(
            "the create of {quoted} {how}, so Datadog may have created it with an id opentide \
             does not know; it is not sent again. Find the rule in Datadog: delete it, or record \
             its id in .opentide/states/deployment/"
        )
    };
    outcome.calls.push("POST");
    let created = match session.create_rule(&rule.body).await {
        Ok(created) => created,
        Err(Failure::NoAnswer(error)) if !matches!(error, ConnectorError::Cancelled) => {
            outcome.failure = Some(
                Event::new(CREATE_UNCONFIRMED, unconfirmed("got no answer"))
                    .with("detail", error.text()),
            );
            return Ok(());
        }
        Err(Failure::Api(error)) if error.status >= 500 || (200..300).contains(&error.status) => {
            let how = if error.status >= 500 {
                format!("got HTTP {}", error.status)
            } else {
                "was answered with no rule".to_owned()
            };
            outcome.failure = Some(
                Event::new(CREATE_UNCONFIRMED, unconfirmed(&how)).with("detail", error.to_string()),
            );
            return Ok(());
        }
        Err(failure) => {
            outcome.failure = Some(rule_failure(failure)?);
            return Ok(());
        }
    };
    let Some(rule_id) = created
        .get("id")
        .map(Json::to_text)
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty())
    else {
        outcome.failure = Some(Event::new(
            CREATE_UNCONFIRMED,
            unconfirmed("was answered with no rule id"),
        ));
        return Ok(());
    };
    outcome.done = Some(("datadog_rule_created", rule_id.clone()));
    outcome.state = StateChange::Record(rule_id);
    Ok(())
}

// ---------------------------------------------------------------------------
// Validation of a rule (`validate query --live` on a block).
// ---------------------------------------------------------------------------

/// `POST /rules/validation` with a block's compiled body: Datadog's
/// `errors[]` are the check's errors (`datadog_rule_invalid`).
///
/// # Errors
///
/// A refused key ([`ConnectorError::Authentication`]), or a tenant that does
/// not answer.
pub async fn check_rule(session: &Session<'_>, body: &Json) -> Result<LiveCheck, ConnectorError> {
    let tenant = session.tenant().to_owned();
    match session.validate_rule(body).await {
        Ok(()) => Ok(LiveCheck::default()),
        Err(Failure::Api(error)) if error.status == 400 => Ok(LiveCheck {
            errors: if error.errors.is_empty() {
                vec![format!("{RULE_INVALID}: {}", error.detail)]
            } else {
                error
                    .errors
                    .iter()
                    .map(|error| format!("{RULE_INVALID}: {error}"))
                    .collect()
            },
            ..LiveCheck::default()
        }),
        // Any other answer, or a rate limit that outlasts the waits, fails
        // this rule only, never a pass.
        Err(Failure::Api(error)) => Ok(LiveCheck {
            errors: vec![format!("{REQUEST_FAILED}: {error}")],
            ..LiveCheck::default()
        }),
        Err(Failure::RateLimited(message)) => Ok(LiveCheck {
            errors: vec![format!("{RATE_LIMITED}: {message}")],
            ..LiveCheck::default()
        }),
        Err(failure) => Err(connector_error(failure, &tenant, "validate the rule")),
    }
}

/// A [`Failure`] as the live check and the query runner report it.
fn connector_error(failure: Failure, tenant: &str, what: &str) -> ConnectorError {
    match failure {
        Failure::Tenant(error) if error.code == UNAUTHORIZED => {
            ConnectorError::authentication(PLATFORM, tenant, error.to_string())
        }
        Failure::Tenant(error) => {
            ConnectorError::refused(PLATFORM, tenant, error.to_string(), None)
        }
        Failure::Api(error) => ConnectorError::refused(
            PLATFORM,
            tenant,
            format!(
                "Datadog could not {what} on {tenant} (HTTP {})",
                error.status
            ),
            Some(error.detail),
        ),
        Failure::RateLimited(message) => {
            ConnectorError::refused(PLATFORM, tenant, format!("{RATE_LIMITED}: {message}"), None)
        }
        Failure::NoAnswer(error) => error,
    }
}

// ---------------------------------------------------------------------------
// Logs Search: the query runner and the live check of a search.
// ---------------------------------------------------------------------------

/// The rows of a Logs Search page: each event's attributes, flattened, its
/// nested `attributes` (the log's own) under their names; and the cursor of
/// the next page.
fn page_rows(payload: &Json) -> (Vec<Row>, Option<String>) {
    let rows = match payload.get("data") {
        Some(Json::Array(events)) => events
            .iter()
            .filter_map(|event| {
                let attributes = event.get("attributes")?.as_object()?;
                let mut row = Row::new();
                if let Some(id) = event.get("id") {
                    row.insert("id".into(), id.clone());
                }
                for (key, value) in attributes {
                    match (key.as_str(), value) {
                        ("attributes", Json::Object(inner)) => {
                            for (name, value) in flatten(inner) {
                                row.insert(format!("@{name}"), value);
                            }
                        }
                        _ => {
                            row.insert(key.clone(), value.clone());
                        }
                    }
                }
                Some(row)
            })
            .collect(),
        _ => Vec::new(),
    };
    let cursor = payload
        .get("meta")
        .and_then(|meta| meta.get("page"))
        .and_then(|page| page.get("after"))
        .and_then(Json::as_str)
        .filter(|cursor| !cursor.is_empty())
        .map(str::to_owned);
    (rows, cursor)
}

/// One Logs Search page: its JSON, or why it has none. A `400` refuses the
/// query with Datadog's message.
async fn search(
    session: &Session<'_>,
    body: &Json,
    timeout: Duration,
) -> Result<Json, ConnectorError> {
    let tenant = session.tenant().to_owned();
    let refused = |message: String, detail: Option<String>| {
        ConnectorError::refused(PLATFORM, &tenant, message, detail)
    };
    let reply = match session.search(body, Some(timeout)).await {
        Ok(reply) => reply,
        Err(failure) => return Err(connector_error(failure, &tenant, "run the search")),
    };
    let action = format!("POST {LOGS_SEARCH_PATH}");
    match reply.answer.status {
        200 => reply.answer.json().ok_or_else(|| {
            refused(
                format!("Datadog did not answer the search with JSON on {tenant}"),
                None,
            )
        }),
        400 => Err(refused(
            format!("Datadog refused the query on {tenant}"),
            Some(api_error(&action, &reply.answer).detail),
        )),
        status => Err(refused(
            format!("Datadog answered HTTP {status} to the search on {tenant}"),
            Some(api_error(&action, &reply.answer).detail),
        )),
    }
}

/// Runs `request` through Logs Search: pages by `meta.page.after` until the
/// limit, at most [`MAX_ROWS`] events. `--index` names the indexes.
///
/// # Errors
///
/// A query Datadog refuses, a refused key, a tenant that does not answer.
pub async fn run_query(
    session: &Session<'_>,
    request: &QueryRequest,
) -> Result<QueryOutcome, ConnectorError> {
    let wanted = request.limit.saturating_add(1).min(MAX_ROWS);
    let mut rows: Vec<Row> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let body = search_body(
            &request.text,
            request.window.start,
            request.window.end,
            wanted - rows.len(),
            &request.index,
            cursor.as_deref(),
        );
        let (page, next) = page_rows(&search(session, &body, request.timeout).await?);
        let empty = page.is_empty();
        rows.extend(page);
        match next {
            Some(next) if !empty && rows.len() < wanted => cursor = Some(next),
            _ => break,
        }
    }
    let shown: Vec<Row> = rows.iter().take(request.limit).cloned().collect();
    let mut warnings = Vec::new();
    if request.limit >= MAX_ROWS && rows.len() >= MAX_ROWS {
        warnings.push(format!(
            "opentide reads at most {MAX_ROWS} Datadog events per search"
        ));
    }
    Ok(QueryOutcome {
        columns: columns_of(&shown),
        truncated: rows.len() > request.limit,
        rows: shown,
        warnings,
        language: Some("datadog".to_owned()),
        ..QueryOutcome::default()
    })
}

/// One event over the request's window: whether Logs Search accepts the
/// query (profile `search`, RFC §8.2). A `200` passes, a `400` refuses the
/// query with Datadog's message.
///
/// # Errors
///
/// As [`run_query`].
pub async fn check_query(
    session: &Session<'_>,
    request: &QueryRequest,
) -> Result<LiveCheck, ConnectorError> {
    let body = search_body(
        &request.text,
        request.window.start,
        request.window.end,
        1,
        &request.index,
        None,
    );
    let (rows, _) = page_rows(&search(session, &body, request.timeout).await?);
    Ok(LiveCheck {
        result: Some(QueryOutcome {
            columns: columns_of(&rows),
            rows,
            language: Some("datadog".to_owned()),
            ..QueryOutcome::default()
        }),
        ..LiveCheck::default()
    })
}

/// The window a search is checked over: the minute before `end`.
pub fn check_window(end: jiff::Timestamp) -> crate::connector::TimeWindow {
    let start = end
        .checked_sub(jiff::SignedDuration::from_mins(
            opentide_compile::datadog::LIVE_WINDOW_MINUTES,
        ))
        .unwrap_or(end);
    crate::connector::TimeWindow { start, end }
}

// ---------------------------------------------------------------------------
// The platform.
// ---------------------------------------------------------------------------

/// The platform: a deployer, a prober, a live validator and a query runner.
pub struct Datadog {
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Datadog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Datadog").finish_non_exhaustive()
    }
}

impl Default for Datadog {
    fn default() -> Self {
        Self::with_clock(Arc::new(SystemClock::default()))
    }
}

impl Datadog {
    /// The platform, waiting on tokio's clock.
    pub fn new() -> Self {
        Self::default()
    }

    /// The platform, waiting on `clock` (a test's).
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }

    /// A session for `cx`.
    ///
    /// # Errors
    ///
    /// As [`Session::new`].
    pub fn session<'a>(&self, cx: TenantContext<'a>) -> Result<Session<'a>, Failure> {
        Session::new(cx, Arc::clone(&self.clock))
    }

    fn connected<'a>(&self, cx: TenantContext<'a>) -> Result<Session<'a>, ConnectorError> {
        let tenant = cx.tenant.label.tenant.clone();
        self.session(cx)
            .map_err(|failure| connector_error(failure, &tenant, "connect"))
    }
}

impl Prober for Datadog {
    /// `GET /security_monitoring/rules?page[size]=1`, a read that changes
    /// nothing. A refused key is `authentication_failed`; any other non-2xx
    /// answer is `tenant_refused`.
    fn probe<'a>(&'a self, cx: TenantContext<'a>) -> BoxFuture<'a, Result<(), DeployError>> {
        crate::connector::probing(async move {
            let tenant = cx.tenant.label.tenant.as_str();
            let session = self.connected(cx)?;
            let status = match session
                .request(
                    &crate::transport::Method::GET,
                    &format!("{RULES_PATH}?page%5Bsize%5D=1"),
                    None,
                    None,
                )
                .await
            {
                Ok(reply) => reply.answer.status,
                Err(failure) => return Err(connector_error(failure, tenant, "list the rules")),
            };
            crate::connector::probe_verdict(PLATFORM, tenant, "listing the detection rules", status)
        })
    }
}

impl Deployer for Datadog {
    /// The tenant's keys and its site, resolved once before its first rule.
    fn open<'a>(&'a self, cx: TenantContext<'a>) -> BoxFuture<'a, Result<(), DeployError>> {
        crate::connector::opening(async move {
            let tenant = cx.tenant.label.tenant.clone();
            match self.session(cx) {
                Ok(_) => Ok(()),
                Err(Failure::NoAnswer(error)) => Err(error),
                Err(failure) => Err(TenantFailure::of(failure).into_error(&tenant)),
            }
        })
    }

    /// One rule from the compiled body: a [`Operation::Disable`] disables, a
    /// delete takes no body. What was done is the outcome's event
    /// (`datadog_rule_created`, `_updated`, `_disabled`, `_deleted`,
    /// or `rule_unchanged`, with its `rule_id`). A rule Datadog refuses fails with its
    /// own code ([`RULE_INVALID`], [`RULE_DEFAULT`], [`RATE_LIMITED`], …); a
    /// refused key or no answer fails the tenant.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        Box::pin(async move {
            let tenant = cx.tenant.label.tenant.as_str();
            let located = |failure: DeployFailure| {
                failure
                    .with_field("platform", PLATFORM)
                    .with_field("tenant", tenant)
            };
            let body: Json = if request.operation == Operation::Delete && request.body.is_empty() {
                Json::Null
            } else {
                serde_json::from_slice(&request.body).map_err(|error| {
                    DeployError::from(ConnectorError::refused(
                        PLATFORM,
                        tenant,
                        format!("the compiled body is not JSON: {error}"),
                        None,
                    ))
                })?
            };
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
                body,
                disable: request.operation == Operation::Disable,
                recreate_refusal: refusal.map(|refusal| (refusal.code, refusal.message.clone())),
            };
            let tenant_failed = |failure: TenantFailure| {
                let mut failed =
                    DeployError::tenant(located(DeployFailure::new(failure.code, failure.message)));
                failed.connector = failure.error;
                failed
            };
            let session = match self.session(cx) {
                Ok(session) => session,
                Err(Failure::NoAnswer(error)) => return Err(DeployError::from(error)),
                Err(failure) => return Err(tenant_failed(TenantFailure::of(failure))),
            };
            let outcome = deploy_rule(&session, &rule).await.map_err(tenant_failed)?;
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
                    .map(|warning| DeployWarning::new(warning.code, warning.message))
                    .collect(),
            )
            .with_events(
                outcome
                    .done
                    .into_iter()
                    .map(|(event, id)| {
                        let mut event = DeployEvent::new(event).with_field("rule_id", id);
                        if !outcome.changed.is_empty() {
                            event = event.with_field("changed", outcome.changed.join(", "));
                        }
                        event
                    })
                    .collect(),
            );
            let Some(failure) = outcome.failure else {
                return Ok(done);
            };
            let refused = refusal.filter(|refusal| {
                refusal.code == failure.code && refusal.message == failure.message
            });
            let mut failed = located(match refused {
                Some(refusal) => refusal.clone(),
                None => DeployFailure::new(failure.code, failure.message),
            });
            for (key, value) in failure.fields {
                failed = failed.with_field(key, value);
            }
            let mut partial = done;
            partial.remote_id = None;
            Err(DeployError::rule(failed).with_partial(partial))
        })
    }
}

impl LiveValidator for Datadog {
    /// A search (profile `search`: a `.datadog` file, a hunt), checked by
    /// Logs Search. A block's rule is validated whole ([`check_rule`]).
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        Box::pin(async move { check_query(&self.connected(cx)?, request).await })
    }
}

impl QueryRunner for Datadog {
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        Box::pin(async move { run_query(&self.connected(cx)?, request).await })
    }
}

impl Platform for Datadog {
    fn id(&self) -> &'static str {
        PLATFORM
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self)
    }

    fn prober(&self) -> Option<&dyn Prober> {
        Some(self)
    }

    fn live_validator(&self) -> Option<&dyn LiveValidator> {
        Some(self)
    }

    fn query_runner(&self) -> Option<&dyn QueryRunner> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> Json {
        serde_json::from_str(text).unwrap_or(Json::Null)
    }

    fn object(text: &str) -> Object {
        match json(text) {
            Json::Object(fields) => fields,
            _ => Object::new(),
        }
    }

    #[test]
    fn an_unchanged_rule_has_no_differences() {
        let compiled = json(
            r#"{"name": "r", "type": "log_detection", "isEnabled": true,
                "queries": [{"name": "a", "query": "x", "dataSource": "logs",
                             "aggregation": "count", "groupByFields": [], "distinctFields": []}],
                "cases": [{"name": "", "status": "high", "condition": "a > 1", "notifications": []}],
                "options": {"detectionMethod": "threshold", "evaluationWindow": 300,
                            "keepAlive": 3600, "maxSignalDuration": 86400,
                            "decreaseCriticalityBasedOnEnv": false},
                "hasExtendedTitle": false, "message": "m", "tags": ["a:1", "b:2"]}"#,
        );
        // What Datadog answers: more keys, defaults, tags in another order.
        let stored = object(
            r#"{"id": "abc-123", "version": 3, "name": "r", "isEnabled": true,
                "isDefault": false, "createdAt": 1, "defaultTags": ["x:y"],
                "queries": [{"name": "a", "query": "x", "dataSource": "logs",
                             "aggregation": "count", "groupByFields": [],
                             "hasOptionalGroupByFields": false, "index": "",
                             "metrics": []}],
                "cases": [{"name": "", "status": "high", "condition": "a > 1",
                           "notifications": [], "actions": []}],
                "options": {"detectionMethod": "threshold", "evaluationWindow": 300.0,
                            "keepAlive": 3600, "maxSignalDuration": 86400,
                            "decreaseCriticalityBasedOnEnv": false,
                            "newValueOptions": {"forgetAfter": 7}},
                "message": "m\n", "tags": ["b:2", "a:1"], "filters": [],
                "type": "log_detection"}"#,
        );
        assert_eq!(differences(&compiled, &stored), Vec::<&str>::new());
    }

    #[test]
    fn each_owned_property_that_differs_is_named() {
        let compiled = json(
            r#"{"name": "r", "isEnabled": true, "queries": [{"query": "x"}],
                "cases": [{"status": "high"}], "options": {"keepAlive": 3600},
                "message": "m", "tags": ["a"], "hasExtendedTitle": true}"#,
        );
        let stored = object(
            r#"{"name": "s", "isEnabled": false, "queries": [{"query": "y"}],
                "cases": [{"status": "high"}, {"status": "low"}],
                "options": {"keepAlive": 60}, "message": "n", "tags": ["a", "b"],
                "groupSignalsBy": ["@usr.id"], "hasExtendedTitle": false}"#,
        );
        assert_eq!(
            differences(&compiled, &stored),
            vec![
                "name",
                "isEnabled",
                "queries",
                "cases",
                "options",
                "message",
                "tags",
                "groupSignalsBy",
                "hasExtendedTitle"
            ]
        );
    }

    #[test]
    fn the_rate_limit_reset_is_seconds() {
        assert_eq!(rate_limit_reset("12"), Some(Duration::from_secs(12)));
        assert_eq!(rate_limit_reset(" 0 "), Some(Duration::ZERO));
        assert_eq!(rate_limit_reset("-1"), None);
        assert_eq!(rate_limit_reset("soon"), None);
    }
}
