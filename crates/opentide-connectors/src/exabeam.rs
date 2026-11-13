//! Exabeam New-Scale SIEM (exabeam-1.0): correlation rules through the
//! Correlation Rules API, and Exabeam Query Language searches through
//! Search, a port of 0.28.0's `platforms/exabeam/{client,deployer,runner,
//! validator}.py`.
//!
//! One [`Session`] serves one tenant for a run. It asks for one bearer token
//! (`POST /auth/v1/token`, client credentials) and reuses it; a `401` whose
//! body or challenge says the token expired gets one new token and one
//! retry. A `401` after that, or a `403`, stops the tenant
//! (`exabeam_tenant_unauthorized`), as a `409` ("Feature is not enabled for
//! subscription") does (`exabeam_feature_unavailable`).
//!
//! Exabeam allows 100 requests a minute per source IP, so every request of
//! every Exabeam session in the process goes through one [`Pacer`]: at most
//! 100 in any rolling minute. A `429` waits out `Retry-After` (60 seconds
//! when absent) and sends the same request again, because a rate-limited
//! request was not executed. No transport-level retry is mounted: a create
//! that got no answer is never sent again (`exabeam_create_unconfirmed`).
//!
//! Deploy plans every create, update, disable and delete from deployment
//! state; the one listing call, the name check before a create, can only
//! refuse the create (`exabeam_name_conflict`): deploy never adopts a rule
//! it finds by name. Every update sends the whole rule (`PUT` replaces it),
//! and a disable is that same `PUT` with `enabled: false`.
//!
//! The bodies are `opentide-compile`'s (`exabeam::compile_rule`).

use std::collections::VecDeque;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Duration;

use opentide_compile::Json;
use opentide_compile::exabeam::{RULES_PATH, SEARCH_PATH, search_body};
use opentide_compile::json::Object;
use opentide_schema::objects::platform::python_strip;
use regex::Regex;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::answer::Answer;
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, LiveCheck, LiveValidator, Operation,
    Platform, QueryOutcome, QueryRequest, QueryRunner, Row, TenantContext, columns_of, flatten,
};
use crate::error::ConnectorError;
use crate::http::HttpSettings;
use crate::{Secret, TenantLabel};

/// The platform's identifier.
pub const PLATFORM: &str = "exabeam";
/// The token endpoint, on the tenant's API host.
pub const TOKEN_PATH: &str = "/auth/v1/token";

/// Exabeam's limit: requests per [`PACE_WINDOW`] per source IP.
pub const PACED_CALLS: usize = 100;
/// The window of [`PACED_CALLS`].
pub const PACE_WINDOW: Duration = Duration::from_secs(60);
/// The wait when a `429` names no `Retry-After`.
pub const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(60);
/// Rate-limited resends of one request before it fails.
pub const MAX_RATE_LIMITED: usize = 10;
/// The longest `Retry-After` waited out; a longer one fails the request
/// instead of stalling the run (a CI job has a timeout).
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);
/// The most rows one search returns (the API's default `limit`).
pub const MAX_ROWS: usize = 3000;
/// The most characters an Exabeam rule name has.
pub const NAME_LIMIT: usize = opentide_schema::objects::platform::exabeam::NAME_LIMIT;

/// A refused API key, at the token endpoint or on a call.
pub const UNAUTHORIZED: &str = "exabeam_tenant_unauthorized";
/// The subscription lacks the feature (`409`).
pub const FEATURE_UNAVAILABLE: &str = "exabeam_feature_unavailable";
/// No token could be had, or the tenant did not answer.
pub const UNREACHABLE: &str = "exabeam_tenant_unreachable";

/// How an Exabeam tenant is reached: 30 s and no transport retries (a
/// create is never sent twice).
pub fn http_defaults() -> HttpSettings {
    HttpSettings {
        timeout: Duration::from_secs(30),
        ..HttpSettings::default()
    }
}

// ---------------------------------------------------------------------------
// The pacer.
// ---------------------------------------------------------------------------

/// At most `calls` requests in any rolling `window` (`_Pacer`). Waits on
/// tokio's clock, so a test pauses it (`tokio::time::pause`).
#[derive(Debug)]
pub struct Pacer {
    calls: Mutex<VecDeque<Instant>>,
    limit: usize,
    window: Duration,
}

impl Default for Pacer {
    fn default() -> Self {
        Self::new(PACED_CALLS, PACE_WINDOW)
    }
}

impl Pacer {
    /// A pacer of `limit` requests per `window`.
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            calls: Mutex::new(VecDeque::new()),
            limit: limit.max(1),
            window,
        }
    }

    fn prune(calls: &mut VecDeque<Instant>, now: Instant, window: Duration) {
        while calls
            .front()
            .is_some_and(|first| now.saturating_duration_since(*first) >= window)
        {
            calls.pop_front();
        }
    }

    /// Waits until one more request fits in the window, and counts it.
    /// Requests wait their turn in order: the lock is held while waiting.
    pub async fn wait(&self) {
        let mut calls = self.calls.lock().await;
        let mut now = Instant::now();
        Self::prune(&mut calls, now, self.window);
        if calls.len() >= self.limit
            && let Some(first) = calls.front().copied()
        {
            let pause = self
                .window
                .saturating_sub(now.saturating_duration_since(first));
            if !pause.is_zero() {
                tokio::time::sleep(pause).await;
            }
            now = Instant::now();
            Self::prune(&mut calls, now, self.window);
        }
        calls.push_back(now);
    }

    /// Forgets every request counted.
    pub async fn reset(&self) {
        self.calls.lock().await.clear();
    }
}

/// The pacer every Exabeam session of the process shares: the limit is per
/// source IP, so every tenant of a run shares it (`PACER`).
pub fn shared_pacer() -> Arc<Pacer> {
    static PACER: LazyLock<Arc<Pacer>> = LazyLock::new(|| Arc::new(Pacer::default()));
    Arc::clone(&PACER)
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

/// The tenant cannot take any request: a refused key, no licence for the
/// feature, no token (`ExabeamTenantError`). It stops the tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantError {
    /// [`UNAUTHORIZED`], [`FEATURE_UNAVAILABLE`] or [`UNREACHABLE`].
    pub code: &'static str,
    /// What happened.
    pub message: String,
}

impl std::fmt::Display for TenantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// A request that failed for this rule or query only (`ExabeamApiError`).
#[derive(Clone, Debug, PartialEq)]
pub struct ApiError {
    /// What was asked (`PUT /correlation-rules/v2/rules/<id>`).
    pub action: String,
    /// The HTTP status.
    pub status: u16,
    /// Exabeam's reason.
    pub detail: String,
    /// Exabeam's `errors[]` entries.
    pub errors: Vec<Json>,
    /// Exabeam's `traceId`.
    pub trace_id: Option<String>,
}

impl ApiError {
    fn new(action: impl Into<String>, status: u16, detail: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            status,
            detail: detail.into(),
            errors: Vec::new(),
            trace_id: None,
        }
    }

    /// Whether Exabeam has no such rule (`404`).
    pub fn not_found(&self) -> bool {
        self.status == 404
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

/// Python's `str()` of a JSON scalar.
fn py_str(value: &Json) -> String {
    match value {
        Json::Null => "None".to_owned(),
        Json::Bool(true) => "True".to_owned(),
        Json::Bool(false) => "False".to_owned(),
        Json::Str(text) => text.clone(),
        other => other.to_compact(),
    }
}

/// One `errors[]` entry as `code: message (fields: a, b)` (`_error_entry`).
fn error_entry(entry: &Object) -> String {
    let code = entry.get("code").filter(|code| code.truthy());
    let message = entry
        .get("message")
        .filter(|message| message.truthy())
        .map(|message| python_strip(&py_str(message)).to_owned())
        .unwrap_or_default();
    let mut text = match code {
        Some(code) if !message.is_empty() => format!("{}: {message}", py_str(code)),
        Some(code) => py_str(code),
        None => message,
    };
    match entry.get("fields") {
        Some(Json::Array(fields)) if !fields.is_empty() => {
            let names: Vec<String> = fields.iter().map(py_str).collect();
            text.push_str(&format!(" (fields: {})", names.join(", ")));
        }
        Some(fields @ (Json::Str(_) | Json::Object(_))) if fields.truthy() => {
            text.push_str(&format!(" (fields: {})", py_str(fields)));
        }
        _ => {}
    }
    text
}

/// The [`ApiError`] a non-2xx answer reports, with Exabeam's details
/// (`api_error`).
pub fn api_error(action: &str, reply: &Reply) -> ApiError {
    let mut error = ApiError::new(action, reply.answer.status, "");
    let mut message = String::new();
    if let Some(Json::Object(payload)) = reply.answer.json() {
        if let Some(Json::Array(entries)) = payload.get("errors") {
            error.errors = entries
                .iter()
                .filter(|entry| matches!(entry, Json::Object(_)))
                .cloned()
                .collect();
        }
        error.trace_id = payload
            .get("traceId")
            .filter(|trace| trace.truthy())
            .map(py_str);
        message = error
            .errors
            .iter()
            .filter_map(Json::as_object)
            .map(error_entry)
            .collect::<Vec<_>>()
            .join("; ");
        if message.is_empty() {
            message = payload
                .get("message")
                .filter(|value| value.truthy())
                .or_else(|| payload.get("error").filter(|value| value.truthy()))
                .map(py_str)
                .unwrap_or_default();
        }
    }
    if message.is_empty() {
        message = reply
            .answer
            .not_json_detail()
            .filter(|detail| !detail.is_empty())
            .or_else(|| Some(reply.answer.text_head(500)).filter(|text| !text.is_empty()))
            .unwrap_or_else(|| reason(reply.answer.status));
    }
    if let Some(trace) = &error.trace_id {
        message = if message.is_empty() {
            format!("traceId {trace}")
        } else {
            format!("{message} (traceId {trace})")
        };
    }
    error.detail = message;
    error
}

/// The status's reason phrase (`response.reason`).
fn reason(status: u16) -> String {
    reqwest::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or_default()
        .to_owned()
}

/// Seconds a `429` asks to wait: `Retry-After` as seconds or an HTTP-date
/// (RFC 9110), [`DEFAULT_RETRY_AFTER`] when absent or neither, zero for a
/// date in the past (`_retry_after`).
pub fn retry_after(value: Option<&str>, now: jiff::Timestamp) -> Duration {
    let value = value.map(str::trim).unwrap_or_default();
    if value.is_empty() {
        return DEFAULT_RETRY_AFTER;
    }
    let seconds = match value.parse::<f64>() {
        Ok(seconds) => seconds,
        Err(_) => match jiff::fmt::rfc2822::parse(value) {
            Ok(when) => {
                let span = when.timestamp().duration_since(now);
                span.as_secs_f64()
            }
            Err(_) => return DEFAULT_RETRY_AFTER,
        },
    };
    if !seconds.is_finite() {
        return DEFAULT_RETRY_AFTER;
    }
    Duration::try_from_secs_f64(seconds.max(0.0)).unwrap_or(DEFAULT_RETRY_AFTER)
}

#[expect(
    clippy::expect_used,
    reason = "a regex literal, exercised by every expired-token case"
)]
fn expired_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"(?i)expired").expect("a valid pattern"))
}

/// An answer and the headers the client reads.
#[derive(Clone, Debug)]
pub struct Reply {
    /// The answer.
    pub answer: Answer,
    /// `Retry-After`.
    pub retry_after: Option<String>,
    /// `WWW-Authenticate`.
    pub challenge: Option<String>,
}

impl Reply {
    /// Whether a `401` says the bearer token expired, in its body or its
    /// challenge (`_token_expired`).
    fn token_expired(&self) -> bool {
        expired_pattern().is_match(&self.answer.text())
            || self
                .challenge
                .as_deref()
                .is_some_and(|challenge| expired_pattern().is_match(challenge))
    }

    /// The body as JSON; `None` for an empty body; an [`ApiError`] for one
    /// that is not JSON (`_json`).
    fn json(&self, action: &str) -> Result<Option<Json>, ApiError> {
        if self.answer.body.is_empty() {
            return Ok(None);
        }
        self.answer.json().map(Some).ok_or_else(|| {
            ApiError::new(
                action,
                self.answer.status,
                self.answer
                    .not_json_detail()
                    .unwrap_or_else(|| "the answer is not JSON".to_owned()),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// The session.
// ---------------------------------------------------------------------------

/// The API base URL of a tenant: `api_url`, else the region's.
pub fn base_url(cx: TenantContext<'_>) -> Result<String, ConnectorError> {
    let api_url = cx
        .tenant
        .secret("api_url")
        .ok()
        .map(|url| url.expose().to_owned());
    let region = match &api_url {
        Some(url) if !url.is_empty() => String::new(),
        _ => cx.tenant.secret("region")?.expose().to_owned(),
    };
    Ok(opentide_schema::configuration::models::exabeam_base_url(
        &region,
        api_url.as_deref(),
    ))
}

/// One tenant's client for a run (`ExabeamClient`): its token, asked for
/// once, and the shared pacer.
#[derive(Debug)]
pub struct Session<'a> {
    cx: TenantContext<'a>,
    base: String,
    pacer: Arc<Pacer>,
    token: Mutex<Option<Secret>>,
}

impl<'a> Session<'a> {
    /// The tenant's session, paced by `pacer` (the process's: [`shared_pacer`]).
    pub fn new(cx: TenantContext<'a>, pacer: Arc<Pacer>) -> Result<Self, ConnectorError> {
        // An unset `$EXABEAM_CLIENT_ID` is refused here, never sent.
        cx.tenant.secret("client_id")?;
        cx.tenant.secret("client_secret")?;
        Ok(Self {
            cx,
            base: base_url(cx)?,
            pacer,
            token: Mutex::new(None),
        })
    }

    /// A session with the token of an earlier session of the run.
    fn with_token(
        cx: TenantContext<'a>,
        pacer: Arc<Pacer>,
        token: Option<Secret>,
    ) -> Result<Self, ConnectorError> {
        let session = Self::new(cx, pacer)?;
        session.token.try_lock().map(|mut held| *held = token).ok();
        Ok(session)
    }

    /// The tenant's name.
    pub fn tenant(&self) -> &str {
        &self.cx.tenant.label.tenant
    }

    /// The API base URL.
    pub fn base(&self) -> &str {
        &self.base
    }

    async fn current_token(&self) -> Option<Secret> {
        self.token.lock().await.clone()
    }

    /// One request, paced, with `429`s waited out. No status is judged
    /// here (`_send`).
    async fn send(
        &self,
        method: &reqwest::Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&Json>,
        token: Option<&Secret>,
        timeout: Option<Duration>,
    ) -> Result<Reply, Failure> {
        let action = format!("{method} {path}");
        let mut url = url::Url::parse(&format!("{}{path}", self.base)).map_err(|error| {
            ConnectorError::Setup {
                platform: PLATFORM.to_owned(),
                tenant: self.tenant().to_owned(),
                message: format!("the API URL is not a URL: {error}"),
            }
        })?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let bytes =
            body.map(serde_json::to_vec)
                .transpose()
                .map_err(|error| ConnectorError::Setup {
                    platform: PLATFORM.to_owned(),
                    tenant: self.tenant().to_owned(),
                    message: error.to_string(),
                })?;
        for _ in 0..=MAX_RATE_LIMITED {
            tokio::select! {
                () = self.cx.cancel.cancelled() => return Err(ConnectorError::Cancelled.into()),
                () = self.pacer.wait() => {}
            }
            let mut builder = self
                .cx
                .http
                .request(method.clone(), url.as_str())
                .header("Accept", "application/json");
            if let Some(bytes) = &bytes {
                builder = builder
                    .header("Content-Type", "application/json")
                    .body(bytes.clone());
            }
            if let Some(token) = token {
                builder = builder.header("Authorization", format!("Bearer {}", token.expose()));
            }
            if let Some(timeout) = timeout {
                builder = builder.timeout(timeout);
            }
            let reply = self.fetch(builder).await?;
            if reply.answer.status != 429 {
                return Ok(reply);
            }
            let wait = retry_after(reply.retry_after.as_deref(), jiff::Timestamp::now());
            if wait > MAX_RETRY_AFTER {
                return Err(ApiError::new(
                    action,
                    429,
                    format!(
                        "rate limited, and Retry-After asks to wait {:.0}s, more than {:.0}s",
                        wait.as_secs_f64(),
                        MAX_RETRY_AFTER.as_secs_f64()
                    ),
                )
                .into());
            }
            tokio::select! {
                () = self.cx.cancel.cancelled() => return Err(ConnectorError::Cancelled.into()),
                () = tokio::time::sleep(wait) => {}
            }
        }
        Err(ApiError::new(
            action,
            429,
            format!("still rate limited after {MAX_RATE_LIMITED} waits"),
        )
        .into())
    }

    async fn fetch(&self, builder: reqwest::RequestBuilder) -> Result<Reply, ConnectorError> {
        let request = builder.build().map_err(|error| ConnectorError::Setup {
            platform: PLATFORM.to_owned(),
            tenant: self.tenant().to_owned(),
            message: crate::error::describe(error),
        })?;
        let started = std::time::Instant::now();
        let response = self.cx.http.send(request, self.cx.cancel).await?;
        let elapsed = started.elapsed();
        let header = |name: reqwest::header::HeaderName| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let retry_after = header(reqwest::header::RETRY_AFTER);
        let challenge = header(reqwest::header::WWW_AUTHENTICATE);
        let content_type = header(reqwest::header::CONTENT_TYPE);
        let status = response.status().as_u16();
        let body = self.cx.http.bytes(response, self.cx.cancel).await?;
        Ok(Reply {
            answer: Answer {
                status,
                content_type,
                body,
                elapsed,
            },
            retry_after,
            challenge,
        })
    }

    fn refused(&self, reply: &Reply, what: &str) -> TenantError {
        let detail = reply
            .answer
            .not_json_detail()
            .unwrap_or_else(|| reply.answer.text_head(300));
        let detail = python_strip(&detail);
        let mut message = format!(
            "tenant {} refused {what}: HTTP {}",
            self.tenant(),
            reply.answer.status
        );
        if !detail.is_empty() {
            message.push_str(&format!(" ({detail})"));
        }
        TenantError {
            code: UNAUTHORIZED,
            message,
        }
    }

    /// The bearer token: asked for once per session, again only when
    /// `refresh` (`token`).
    pub async fn token(&self, refresh: bool) -> Result<Secret, Failure> {
        let mut held = self.token.lock().await;
        if let Some(token) = held.as_ref().filter(|_| !refresh) {
            return Ok(token.clone());
        }
        let action = format!("POST {TOKEN_PATH}");
        let mut body = Object::new();
        body.insert(
            "client_id".into(),
            self.cx.tenant.secret("client_id")?.expose().into(),
        );
        body.insert(
            "client_secret".into(),
            self.cx.tenant.secret("client_secret")?.expose().into(),
        );
        body.insert("grant_type".into(), "client_credentials".into());
        let reply = self
            .send(
                &reqwest::Method::POST,
                TOKEN_PATH,
                &[],
                Some(&Json::Object(body)),
                None,
                None,
            )
            .await?;
        let status = reply.answer.status;
        if matches!(status, 400 | 401 | 403) {
            return Err(self.refused(&reply, "the API key").into());
        }
        if status >= 300 {
            return Err(api_error(&action, &reply).into());
        }
        // The answer is a bearer credential: never logged nor quoted.
        let Some(payload) = reply.answer.json() else {
            return Err(ApiError::new(action, status, "the answer is not JSON").into());
        };
        let token = payload
            .get("access_token")
            .and_then(Json::as_str)
            .filter(|token| !token.is_empty())
            .map(|token| Secret::new(token.to_owned()));
        let Some(token) = token else {
            return Err(ApiError::new(action, status, "the answer has no access_token").into());
        };
        *held = Some(token.clone());
        Ok(token)
    }

    /// The token for a request, or the [`TenantError`] that stops the
    /// tenant: the request itself was never sent, so a create that needed
    /// it is not unconfirmed (`_token_for`).
    async fn token_for(&self, action: &str, refresh: bool) -> Result<Secret, Failure> {
        match self.token(refresh).await {
            Ok(token) => Ok(token),
            Err(Failure::NoAnswer(ConnectorError::Cancelled)) => {
                Err(ConnectorError::Cancelled.into())
            }
            Err(Failure::Api(error)) => Err(self.unreachable(action, &error.to_string()).into()),
            Err(Failure::NoAnswer(error)) => Err(self.unreachable(action, &error.text()).into()),
            Err(Failure::Tenant(error)) => Err(error.into()),
        }
    }

    fn unreachable(&self, action: &str, error: &str) -> TenantError {
        TenantError {
            code: UNREACHABLE,
            message: format!("tenant {}: no token for {action}: {error}", self.tenant()),
        }
    }

    /// An authenticated request. A `401` or `403` refuses the tenant, as a
    /// `409` does; every other answer is the caller's to judge (`request`).
    pub async fn request(
        &self,
        method: &reqwest::Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&Json>,
        timeout: Option<Duration>,
    ) -> Result<Reply, Failure> {
        let action = format!("{method} {path}");
        let mut refreshed = false;
        loop {
            let token = self.token_for(&action, false).await?;
            let reply = self
                .send(method, path, query, body, Some(&token), timeout)
                .await?;
            let status = reply.answer.status;
            if status == 401 && !refreshed && reply.token_expired() {
                refreshed = true;
                self.token_for(&action, true).await?;
                continue;
            }
            if matches!(status, 401 | 403) {
                return Err(self.refused(&reply, &action).into());
            }
            if status == 409 {
                let detail = api_error(&action, &reply).detail;
                return Err(TenantError {
                    code: FEATURE_UNAVAILABLE,
                    message: format!(
                        "tenant {} answered {action} with HTTP 409: {}",
                        self.tenant(),
                        if detail.is_empty() {
                            "the feature is not enabled for the subscription"
                        } else {
                            &detail
                        }
                    ),
                }
                .into());
            }
            return Ok(reply);
        }
    }

    /// `GET /correlation-rules/v2/rules?nameContains=<name>`: the rules whose
    /// name holds `name`. The API answers one array, with no paging
    /// (`rules_named`).
    pub async fn rules_named(&self, name: &str) -> Result<Vec<Object>, Failure> {
        let action = format!("GET {RULES_PATH}?nameContains");
        let reply = self
            .request(
                &reqwest::Method::GET,
                RULES_PATH,
                &[("nameContains", name)],
                None,
                None,
            )
            .await?;
        if reply.answer.status >= 300 {
            return Err(api_error(&action, &reply).into());
        }
        let mut payload = reply.json(&action)?;
        if let Some(Json::Object(wrapper)) = &payload {
            // A wrapped list is read only under a known key: any other shape
            // is refused, never read as "no rule has this name".
            let listed: Vec<&Json> = ["rules", "items"]
                .iter()
                .filter_map(|key| wrapper.get(*key))
                .collect();
            payload = match listed.as_slice() {
                [one] => Some((*one).clone()),
                _ => None,
            };
        }
        let Some(Json::Array(rules)) = payload else {
            return Err(ApiError::new(
                action,
                reply.answer.status,
                "the answer is not a list of rules",
            )
            .into());
        };
        Ok(rules
            .into_iter()
            .filter_map(|rule| match rule {
                Json::Object(rule) => Some(rule),
                _ => None,
            })
            .collect())
    }

    async fn rule_call(
        &self,
        method: &reqwest::Method,
        path: &str,
        body: &Json,
    ) -> Result<Object, Failure> {
        let action = format!("{method} {path}");
        let reply = self.request(method, path, &[], Some(body), None).await?;
        if reply.answer.status >= 300 {
            return Err(api_error(&action, &reply).into());
        }
        Ok(match reply.json(&action)? {
            Some(Json::Object(rule)) => rule,
            _ => Object::new(),
        })
    }

    /// `POST /correlation-rules/v2/rules`: the rule Exabeam created.
    pub async fn create_rule(&self, body: &Json) -> Result<Object, Failure> {
        self.rule_call(&reqwest::Method::POST, RULES_PATH, body)
            .await
    }

    /// `PUT /correlation-rules/v2/rules/{id}`: the rule as Exabeam stored it.
    pub async fn update_rule(&self, rule_id: &str, body: &Json) -> Result<Object, Failure> {
        self.rule_call(
            &reqwest::Method::PUT,
            &format!("{RULES_PATH}/{rule_id}"),
            body,
        )
        .await
    }

    /// `DELETE /correlation-rules/v2/rules/{id}`; a `404` is an [`ApiError`]
    /// whose [`ApiError::not_found`] holds.
    pub async fn delete_rule(&self, rule_id: &str) -> Result<(), Failure> {
        let path = format!("{RULES_PATH}/{rule_id}");
        let reply = self
            .request(&reqwest::Method::DELETE, &path, &[], None, None)
            .await?;
        if reply.answer.status >= 300 {
            return Err(api_error(&format!("DELETE {path}"), &reply).into());
        }
        Ok(())
    }

    /// `POST /search/v2/events`; the answer whatever its status (`search`).
    pub async fn search(&self, body: &Json, timeout: Option<Duration>) -> Result<Reply, Failure> {
        self.request(
            &reqwest::Method::POST,
            SEARCH_PATH,
            &[],
            Some(body),
            timeout,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Deploy.
// ---------------------------------------------------------------------------

/// What a deploy does to the rule on the tenant (`ExternalIdAction`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// No id is recorded: create the rule, unless one has its name.
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
    /// The Exabeam rule name.
    pub name: String,
    /// Whether the block's status is a DISABLEMENT.
    pub disable: bool,
    /// Why deployment state cannot take a rule created again, when it cannot
    /// (`deployment_state_ignore`, `unpersisted_error`): the code and the
    /// message. A recorded rule the tenant lost is then not created again.
    pub recreate_refusal: Option<(String, String)>,
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

/// A warning or an error a deploy raises, with its log fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// The code (`exabeam_name_conflict`).
    pub code: String,
    /// What happened (the log's `error`, or `detail` for a warning).
    pub message: String,
    /// More fields of the log line (`detail`, `existing_id`, `errors`,
    /// `trace_id`, and `name` on the create path).
    pub fields: Vec<(&'static str, String)>,
}

impl Event {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
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
    /// What was done (`exabeam_rule_created`, `_updated`, `_disabled`,
    /// `_deleted`), with the rule id, when it was.
    pub done: Option<(&'static str, String)>,
    /// Warnings raised (`DEPLOYMENT_WARNING_RAISED`).
    pub warnings: Vec<Event>,
    /// The rule's failure (`DEPLOYMENT_ERROR_RAISED`).
    pub failure: Option<Event>,
}

impl RuleOutcome {
    fn new() -> Self {
        Self {
            state: StateChange::Keep,
            done: None,
            warnings: Vec::new(),
            failure: None,
        }
    }
}

/// A failure that stops the tenant: its code and its text
/// (`exabeam_tenant_deployment_failed`).
#[derive(Debug)]
pub struct TenantFailure {
    /// [`UNAUTHORIZED`], [`FEATURE_UNAVAILABLE`] or [`UNREACHABLE`].
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

/// The rule UUID a create answered, lower-case and canonical, or `None`
/// (`returned_rule_id`).
pub fn returned_rule_id(result: &Object) -> Option<String> {
    let value = python_strip(result.get("id")?.as_str()?);
    let canonical = uuid::Uuid::try_parse(value).ok()?;
    // Only the hyphenated 8-4-4-4-12 form, as the oracle's pattern takes it.
    (value.len() == 36).then(|| canonical.hyphenated().to_string())
}

/// The rules whose name is `name`, compared case-insensitively and exactly:
/// `nameContains` matches substrings (`name_matches`).
pub fn name_matches<'r>(rules: &'r [Object], name: &str) -> Vec<&'r Object> {
    let wanted = caseless_fold(name);
    rules
        .iter()
        .filter(|rule| caseless_fold(&rule.get("name").map(py_str).unwrap_or_default()) == wanted)
        .collect()
}

/// `str.casefold()`, for the names Exabeam compares.
fn caseless_fold(text: &str) -> String {
    text.chars()
        .flat_map(char::to_lowercase)
        .collect::<String>()
        .replace('ß', "ss")
}

/// Whether the rule a `PUT` returned keeps a schedule the block no longer
/// sets (`schedule_retained`).
pub fn schedule_retained(stored: &Object, has_schedule: bool) -> bool {
    if has_schedule {
        return false;
    }
    match stored.get("scheduleConfig") {
        Some(Json::Object(config)) => config.get("recurrences").is_some_and(Json::truthy),
        Some(other) => other.truthy(),
        None => false,
    }
}

fn failed(error: &ApiError) -> Event {
    if error.status == 400 {
        let mut event = Event::new("exabeam_request_rejected", error.to_string());
        if !error.errors.is_empty() {
            let kept: Vec<Json> = error
                .errors
                .iter()
                .filter_map(Json::as_object)
                .map(|entry| {
                    let mut kept = Object::new();
                    for key in ["code", "message", "fields"] {
                        if let Some(value) = entry.get(key) {
                            kept.insert(key.into(), value.clone());
                        }
                    }
                    Json::Object(kept)
                })
                .collect();
            event = event.with("errors", Json::Array(kept).to_compact());
        }
        if let Some(trace) = &error.trace_id {
            event = event.with("trace_id", trace.clone());
        }
        event
    } else {
        Event::new("exabeam_request_failed", error.to_string())
    }
}

/// Deploys one rule (`ExabeamDeploy.deploy_rule`). A rule's failure is in
/// the outcome; an `Err` stops the tenant: a refused key, no licence, no
/// token, or a request other than a create that got no answer.
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
        Action::Delete(rule_id) => {
            match session.delete_rule(rule_id).await {
                Ok(()) => {}
                Err(Failure::Api(error)) if error.not_found() => {}
                Err(Failure::Api(error)) => {
                    outcome.failure = Some(failed(&error));
                    return Ok(());
                }
                Err(other) => return Err(other),
            }
            outcome.done = Some(("exabeam_rule_deleted", rule_id.clone()));
            outcome.state = StateChange::Forget;
            return Ok(());
        }
        Action::Create | Action::Update(_) if rule.name.chars().count() > NAME_LIMIT => {
            // validate reports it too; a deploy never sends a name Exabeam refuses.
            outcome.failure = Some(Event::new(
                "exabeam_name_length",
                format!(
                    "the Exabeam rule name is {} characters, more than {NAME_LIMIT}: set a \
                     shorter configurations.exabeam.name",
                    rule.name.chars().count()
                ),
            ));
            return Ok(());
        }
        Action::Create => return create(session, rule, outcome).await,
        Action::Update(rule_id) => rule_id,
    };
    let stored = match session.update_rule(rule_id, &rule.body).await {
        Ok(stored) => stored,
        Err(Failure::Api(error)) if error.not_found() => {
            return recreate(session, rule, outcome).await;
        }
        Err(Failure::Api(error)) => {
            outcome.failure = Some(failed(&error));
            return Ok(());
        }
        Err(other) => return Err(other),
    };
    outcome.done = Some((
        if rule.disable {
            "exabeam_rule_disabled"
        } else {
            "exabeam_rule_updated"
        },
        rule_id.clone(),
    ));
    let has_schedule = rule.body.get("scheduleConfig").is_some();
    if schedule_retained(&stored, has_schedule) {
        outcome.warnings.push(Event::new(
            "exabeam_schedule_retained",
            format!(
                "Exabeam rule {rule_id} keeps a schedule the block no longer sets; clear it in \
                 the console"
            ),
        ));
    }
    if stored.get("autoDisabled") == Some(&Json::Bool(true)) {
        outcome.warnings.push(Event::new(
            "exabeam_rule_auto_disabled",
            format!(
                "Exabeam stopped rule {rule_id} (autoDisabled): it matched or triggered too \
                 often, or its query or context table is broken"
            ),
        ));
    }
    Ok(())
}

/// The create path (`_create`): its failures name the Exabeam rule
/// (`name`, the compiled name), where the update path's name the object.
async fn create(
    session: &Session<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), Failure> {
    let sent = create_unnamed(session, rule, outcome).await;
    if let Some(failure) = &mut outcome.failure {
        failure.fields.push(("name", rule.name.clone()));
    }
    sent
}

async fn create_unnamed(
    session: &Session<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), Failure> {
    let name = &rule.name;
    let listed = match session.rules_named(name).await {
        Ok(listed) => listed,
        Err(Failure::Api(error)) => {
            outcome.failure = Some(failed(&error));
            return Ok(());
        }
        Err(other) => return Err(other),
    };
    let existing = name_matches(&listed, name);
    if !existing.is_empty() {
        let ids = existing
            .iter()
            .map(|rule| rule.get("id").map_or_else(|| "?".to_owned(), py_str))
            .collect::<Vec<_>>()
            .join(", ");
        outcome.failure = Some(
            Event::new(
                "exabeam_name_conflict",
                format!(
                    "an Exabeam rule named {} already exists (id {ids}); deploy does not adopt \
                     it. Rename the block (name) or delete the other rule",
                    opentide_schema::configuration::repr::quote(name)
                ),
            )
            .with("existing_id", ids),
        );
        return Ok(());
    }
    let quoted = opentide_schema::configuration::repr::quote(name);
    let unconfirmed = |how: &str| {
        format!(
            "the create of {quoted} {how}, so Exabeam may have created it with an id opentide \
             does not know; it is not sent again. Find the rule in the console: delete it, or \
             record its id in .opentide/states/deployment/"
        )
    };
    let result = match session.create_rule(&rule.body).await {
        Ok(result) => result,
        Err(Failure::NoAnswer(error)) => {
            outcome.failure = Some(
                Event::new("exabeam_create_unconfirmed", unconfirmed("got no answer"))
                    .with("detail", error.text()),
            );
            return Ok(());
        }
        Err(Failure::Api(error)) if (200..300).contains(&error.status) => {
            // Exabeam created the rule but its answer cannot be read: no id to keep.
            outcome.failure = Some(
                Event::new(
                    "exabeam_create_no_id",
                    format!(
                        "the create of {quoted} was accepted (HTTP {}) but its answer is not a \
                         rule: the rule may exist on the tenant without a binding: remove it in \
                         the console",
                        error.status
                    ),
                )
                .with("detail", error.to_string()),
            );
            return Ok(());
        }
        Err(Failure::Api(error)) if error.status >= 500 => {
            outcome.failure = Some(
                Event::new(
                    "exabeam_create_unconfirmed",
                    unconfirmed(&format!("got HTTP {}", error.status)),
                )
                .with("detail", error.to_string()),
            );
            return Ok(());
        }
        Err(Failure::Api(error)) => {
            outcome.failure = Some(failed(&error));
            return Ok(());
        }
        Err(other) => return Err(other),
    };
    let Some(rule_id) = returned_rule_id(&result) else {
        let id = result.get("id").map_or_else(
            || "None".to_owned(),
            |id| match id {
                Json::Str(text) => opentide_schema::configuration::repr::quote(text),
                other => py_str(other),
            },
        );
        outcome.failure = Some(Event::new(
            "exabeam_create_no_id",
            format!(
                "the create of {quoted} answered no rule UUID (id {id}); the rule may exist on \
                 the tenant without a binding: remove it in the console"
            ),
        ));
        return Ok(());
    };
    outcome.done = Some(("exabeam_rule_created", rule_id.clone()));
    outcome.state = StateChange::Record(rule_id);
    Ok(())
}

/// The bound rule is gone (`PUT` 404): create it again, or forget it under
/// a DISABLEMENT (`_recreate`).
async fn recreate(
    session: &Session<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), Failure> {
    if rule.disable {
        outcome.warnings.push(Event::new(
            "exabeam_rule_missing",
            "the recorded rule no longer exists on the tenant; its id is removed",
        ));
        outcome.state = StateChange::Forget;
        return Ok(());
    }
    outcome.warnings.push(Event::new(
        "exabeam_rule_recreated",
        "the recorded rule no longer exists on the tenant; creating it again",
    ));
    if let Some((code, message)) = &rule.recreate_refusal {
        outcome.failure = Some(Event::new(code, message.clone()));
        return Ok(());
    }
    create(session, rule, outcome).await
}

// ---------------------------------------------------------------------------
// Search: the query runner and the live check.
// ---------------------------------------------------------------------------

#[expect(
    clippy::expect_used,
    reason = "regex literals, exercised by every SELECT case"
)]
fn select_patterns() -> &'static (Regex, Regex, Regex) {
    static PATTERNS: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        (
            Regex::new(r"(?i)^\s*SELECT\s+(?:DISTINCT\s+)?").expect("a valid pattern"),
            Regex::new(r"(?i)\b(?:FROM|WHERE|GROUP-BY|ORDER-BY|LIMIT)\b|\|")
                .expect("a valid pattern"),
            Regex::new(r"(?i)\s+AS\s+([A-Za-z_][A-Za-z0-9_]*)\s*$").expect("a valid pattern"),
        )
    })
}

/// `text` split at the commas outside brackets and strings (`_split_columns`).
fn split_columns(text: &str) -> Vec<String> {
    let mut columns = Vec::new();
    let mut depth: i64 = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut current = String::new();
    for character in text.chars() {
        if let Some(open) = quote {
            current.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == open {
                quote = None;
            }
            continue;
        }
        match character {
            '"' | '\'' => quote = Some(character),
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                columns.push(python_strip(&current).to_owned());
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(character);
    }
    columns.push(python_strip(&current).to_owned());
    columns.retain(|column| !column.is_empty());
    columns
}

/// The columns a `SELECT` names, each by its `AS` name when it has one;
/// empty for `SELECT *` or a query without `SELECT` (`selected_columns`).
pub fn selected_columns(query: &str) -> Vec<String> {
    let (select, clause, alias) = select_patterns();
    let Some(head) = select.find(query) else {
        return Vec::new();
    };
    let rest = &query[head.end()..];
    let end = clause.find(rest).map_or(rest.len(), |found| found.start());
    let columns = split_columns(&rest[..end]);
    if columns.is_empty() || columns == ["*"] {
        return Vec::new();
    }
    columns
        .into_iter()
        .map(|column| {
            alias
                .captures(&column)
                .and_then(|captures| captures.get(1))
                .map_or_else(|| column.clone(), |name| name.as_str().to_owned())
        })
        .collect()
}

/// The answer's rows, flattened, and its `totalRows` (`_rows`).
fn rows(payload: &Json) -> (Vec<Row>, Option<i64>) {
    let Json::Object(payload) = payload else {
        return (Vec::new(), None);
    };
    let rows = match payload.get("rows") {
        Some(Json::Array(rows)) => rows
            .iter()
            .filter_map(Json::as_object)
            .map(flatten)
            .collect(),
        _ => Vec::new(),
    };
    let total = match payload.get("totalRows") {
        Some(Json::Int(total)) => Some(*total),
        _ => None,
    };
    (rows, total)
}

/// `POST /search/v2/events`: the answer's JSON, or the reason it has none
/// (`_search`).
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
        Err(Failure::Tenant(error)) => {
            return Err(ConnectorError::authentication(
                PLATFORM,
                &tenant,
                error.to_string(),
            ));
        }
        Err(Failure::Api(error)) => {
            return Err(refused(
                format!("Exabeam could not run the search on {tenant}"),
                Some(error.detail),
            ));
        }
        // The search has no cancel: stopping waiting closes the connection.
        Err(Failure::NoAnswer(error)) => return Err(error),
    };
    let action = format!("POST {SEARCH_PATH}");
    match reply.answer.status {
        200 => reply.answer.json().ok_or_else(|| {
            refused(
                format!("Exabeam did not answer the search with JSON on {tenant}"),
                None,
            )
        }),
        400 => Err(refused(
            format!("Exabeam refused the query on {tenant}"),
            Some(api_error(&action, &reply).detail),
        )),
        status => Err(refused(
            format!("Exabeam answered HTTP {status} to the search on {tenant}"),
            Some(api_error(&action, &reply).detail),
        )),
    }
}

/// Runs `request` on the tenant (`ExabeamQueryRunner.run`): at most 3,000
/// rows, the query's `SELECT` columns or every field.
pub async fn run_query(
    session: &Session<'_>,
    request: &QueryRequest,
) -> Result<QueryOutcome, ConnectorError> {
    let limit = request.limit.saturating_add(1).min(MAX_ROWS);
    let body = search_body(
        &request.text,
        request.window.start,
        request.window.end,
        limit,
        &selected_columns(&request.text),
    );
    let (rows, total) = rows(&search(session, &body, request.timeout).await?);
    let shown: Vec<Row> = rows.iter().take(request.limit).cloned().collect();
    let mut warnings = Vec::new();
    if request.limit >= MAX_ROWS {
        warnings.push("Exabeam returns at most 3,000 rows per search".to_owned());
    }
    let truncated = rows.len() > request.limit
        || total.is_some_and(|total| {
            usize::try_from(total).map_or(total > 0, |total| total > shown.len())
        });
    Ok(QueryOutcome {
        columns: columns_of(&shown),
        rows: shown,
        truncated,
        warnings,
        language: Some("exabeam".to_owned()),
        ..QueryOutcome::default()
    })
}

/// One row over `request.window`, every field: whether the tenant accepts
/// the filter (`ExabeamQueryRunner.check`). A `200` passes, a `400`
/// refuses the query with Exabeam's message, any other answer fails.
pub async fn check_query(
    session: &Session<'_>,
    request: &QueryRequest,
) -> Result<LiveCheck, ConnectorError> {
    let body = search_body(
        &request.text,
        request.window.start,
        request.window.end,
        1,
        &[],
    );
    let (rows, _) = rows(&search(session, &body, request.timeout).await?);
    Ok(LiveCheck {
        result: Some(QueryOutcome {
            columns: columns_of(&rows),
            rows,
            language: Some("exabeam".to_owned()),
            ..QueryOutcome::default()
        }),
        ..LiveCheck::default()
    })
}

/// The window a rule's sequence filters are checked over: the 15 minutes
/// before `end`, the console's "Test Last 15 mins" (`ExabeamQueryValidator`).
pub fn rule_check_window(end: jiff::Timestamp) -> crate::connector::TimeWindow {
    let start = end
        .checked_sub(jiff::SignedDuration::from_mins(
            opentide_compile::exabeam::LIVE_WINDOW_MINUTES,
        ))
        .unwrap_or(end);
    crate::connector::TimeWindow { start, end }
}

// ---------------------------------------------------------------------------
// The platform.
// ---------------------------------------------------------------------------

/// The platform: a deployer, a live validator and a query runner, every
/// session paced by the process's pacer.
#[derive(Debug)]
pub struct Exabeam {
    pacer: Arc<Pacer>,
    /// The token of each tenant the deployer reached in this run.
    tokens: Mutex<std::collections::BTreeMap<TenantLabel, Secret>>,
}

impl Default for Exabeam {
    fn default() -> Self {
        Self::with_pacer(shared_pacer())
    }
}

impl Exabeam {
    /// The platform, paced by the process's pacer.
    pub fn new() -> Self {
        Self::default()
    }

    /// The platform, paced by `pacer`.
    pub fn with_pacer(pacer: Arc<Pacer>) -> Self {
        Self {
            pacer,
            tokens: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    /// A session for `cx`.
    pub fn session<'a>(&self, cx: TenantContext<'a>) -> Result<Session<'a>, ConnectorError> {
        Session::new(cx, Arc::clone(&self.pacer))
    }
}

impl Deployer for Exabeam {
    /// One rule from the compiled body alone: its name is the body's, a
    /// [`Operation::Disable`] disables. A rule's failure is an error here.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        Box::pin(async move {
            let body: Json = serde_json::from_slice(&request.body).map_err(|error| {
                ConnectorError::refused(
                    PLATFORM,
                    &cx.tenant.label.tenant,
                    format!("the compiled body is not JSON: {error}"),
                    None,
                )
            })?;
            let name = body
                .get("name")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned();
            let action = match request.operation {
                Operation::Create => Action::Create,
                Operation::Update | Operation::Disable => Action::Update(request.rule_id.clone()),
                Operation::Delete => Action::Delete(request.rule_id.clone()),
            };
            let rule = RuleDeploy {
                action,
                body,
                name,
                disable: request.operation == Operation::Disable,
                recreate_refusal: None,
            };
            let token = self.tokens.lock().await.get(&cx.tenant.label).cloned();
            let session = Session::with_token(cx, Arc::clone(&self.pacer), token)?;
            let result = deploy_rule(&session, &rule).await;
            if let Some(token) = session.current_token().await {
                self.tokens
                    .lock()
                    .await
                    .insert(cx.tenant.label.clone(), token);
            }
            let outcome = result.map_err(|failure| failure.into_error(&cx.tenant.label.tenant))?;
            if let Some(failure) = outcome.failure {
                return Err(ConnectorError::refused(
                    PLATFORM,
                    &cx.tenant.label.tenant,
                    format!("{}: {}", failure.code, failure.message),
                    None,
                ));
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

impl LiveValidator for Exabeam {
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        Box::pin(async move { check_query(&self.session(cx)?, request).await })
    }
}

impl QueryRunner for Exabeam {
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        Box::pin(async move { run_query(&self.session(cx)?, request).await })
    }
}

impl Platform for Exabeam {
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

#[cfg(test)]
#[path = "exabeam_tests.rs"]
mod tests;
