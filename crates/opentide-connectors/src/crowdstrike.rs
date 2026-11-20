//! CrowdStrike Falcon (UC-4.2, #832): the correlation rules a deploy sends
//! and the Next-Gen SIEM (LogScale) query jobs `opentide query` runs.
//!
//! A port of `platforms/crowdstrike/client.py` (`CrowdstrikeService`: the
//! OAuth2 client-credentials token, then create, update and delete),
//! `deployer.py` (a token per tenant, then one request per rule)
//! and `runner.py` (a query job started, polled until done and stopped when
//! the runner stops waiting for it), request for request. CrowdStrike has no
//! live validation: the platform has no [`crate::connector::LiveValidator`]
//! (`supported: False`).
//!
//! The token comes from the cloud's own OAuth2 endpoint
//! (`<api>/oauth2/token`), never Entra ID's, and is kept in the platform's
//! [`TokenCache`] until five minutes before its `expires_in`, for deploys
//! and searches alike; a `401` gets one new token and one resend.
//!
//! The rule bodies are `opentide-compile`'s (`crowdstrike::compile`), as
//! bytes: a create's correlation rule, an update's (or a disable's) one-rule
//! list with the id.

use std::sync::Arc;
use std::time::Duration;

use opentide_compile::Json;
use opentide_compile::deploy::PATH_SEGMENT;
use percent_encoding::utf8_percent_encode;
use tokio_util::sync::CancellationToken;

use crate::Secret;
use crate::answer::Answer;
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, Operation, Platform, Prober, QueryOutcome,
    QueryRequest, QueryRunner, Row, TenantContext, columns_of, flatten, probe_verdict,
};
use crate::error::ConnectorError;
use crate::http::HttpSettings;
use crate::retry::RetryPolicy;
use crate::token::{Issued, TokenCache, lifetime};

/// The platform's identifier.
pub const PLATFORM: &str = "crowdstrike";

/// The repository a search reads when `--index` names none: every event
/// Falcon holds.
pub const DEFAULT_REPOSITORY: &str = "search-all";

/// The correlation rules endpoint, after the cloud's API.
const RULES: &str = "/correlation-rules/entities/rules/v1";

/// The correlation rule ids endpoint, after the cloud's API (what a probe
/// lists, one id).
const RULE_IDS: &str = "/correlation-rules/queries/rules/v1";

/// The first wait between two polls of a search, doubled up to
/// [`MAX_POLL_DELAY`].
const FIRST_POLL_DELAY: Duration = Duration::from_millis(500);
/// The longest wait between two polls.
const MAX_POLL_DELAY: Duration = Duration::from_secs(5);
/// How long stopping a search may take once the runner gave up on it.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// How a CrowdStrike tenant is reached when nothing else says: 120 s and
/// the connectors' retries.
pub fn http_defaults() -> HttpSettings {
    HttpSettings {
        retry: RetryPolicy::standard(),
        ..HttpSettings::default()
    }
}

/// The API of a tenant's cloud (`_get_base_api`), or the setup error.
pub fn base_api(cx: TenantContext<'_>) -> Result<&'static str, ConnectorError> {
    let domain = cx.tenant.secret("api")?;
    opentide_compile::crowdstrike::base_api(domain.expose()).map_err(|_| ConnectorError::Setup {
        platform: PLATFORM.to_owned(),
        tenant: cx.tenant.label.tenant.clone(),
        message: "Invalid API Domain: the api is one of US-1, US-2, EU-1, US-GOV-1, US-GOV-2"
            .to_owned(),
    })
}

fn refused(cx: TenantContext<'_>, message: String, detail: Option<String>) -> ConnectorError {
    ConnectorError::Refused {
        platform: PLATFORM.to_owned(),
        tenant: cx.tenant.label.tenant.clone(),
        message,
        detail,
    }
}

fn build(
    builder: crate::transport::RequestBuilder,
    cx: TenantContext<'_>,
) -> Result<crate::transport::Request, ConnectorError> {
    builder.build().map_err(|error| ConnectorError::Setup {
        platform: PLATFORM.to_owned(),
        tenant: cx.tenant.label.tenant.clone(),
        message: error.describe(),
    })
}

/// Signs in to the cloud at *base* with the tenant's `client_id` and
/// `client_secret`: a form `POST` to `/oauth2/token`, answered 201 with an
/// `access_token` and its `expires_in`.
async fn sign_in(cx: TenantContext<'_>, base: &str) -> Result<Issued, ConnectorError> {
    sign_in_as(cx, base, false).await
}

/// The refusal of the token endpoint's answer *status* as a connectivity
/// probe tells it (`opentide doctor --live`): 400, 401 and 403 refuse the
/// credentials ([`ConnectorError::Authentication`]); a gateway's 502, 503 or
/// 504 is [`ConnectorError::Gateway`]; any other status (a 429, a 500) is the
/// tenant's own refusal. A rate-limited or failing token endpoint is never
/// reported as bad credentials.
fn token_refusal(cx: TenantContext<'_>, status: u16) -> ConnectorError {
    let tenant = &cx.tenant.label.tenant;
    let message = format!("Cannot authenticate against {tenant} (HTTP {status})");
    match status {
        400 | 401 | 403 => ConnectorError::authentication(PLATFORM, tenant, message),
        502..=504 => ConnectorError::Gateway {
            platform: PLATFORM.to_owned(),
            tenant: tenant.clone(),
            message,
            status,
        },
        _ => refused(cx, message, None),
    }
}

/// [`sign_in`], with the refusal told by [`token_refusal`] when *probing*.
async fn sign_in_as(
    cx: TenantContext<'_>,
    base: &str,
    probing: bool,
) -> Result<Issued, ConnectorError> {
    let client_id = cx.tenant.secret("client_id")?;
    let client_secret = cx.tenant.secret("client_secret")?;
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id.expose())
        .append_pair("client_secret", client_secret.expose())
        .finish();
    let request = build(
        cx.http
            .request(
                crate::transport::Method::POST,
                &format!("{base}/oauth2/token"),
            )
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form)
            // A sign-in writes no rule (`HttpClient::writes_taken`).
            .read_only(),
        cx,
    )?;
    let answer = Answer::fetch(cx.http, request, cx.cancel).await?;
    let tenant = &cx.tenant.label.tenant;
    if answer.status != 201 {
        if probing {
            return Err(token_refusal(cx, answer.status));
        }
        return Err(refused(
            cx,
            format!(
                "Cannot authenticate against {tenant} (HTTP {})",
                answer.status
            ),
            None,
        ));
    }
    // The answer is a bearer credential: never logged nor quoted.
    let body = answer.json();
    let token = body
        .as_ref()
        .and_then(|body| body.get("access_token").and_then(Json::as_str))
        .filter(|token| !token.is_empty());
    match token {
        Some(token) => Ok(Issued {
            token: Secret::new(token),
            lifetime: lifetime(body.as_ref().and_then(|body| body.get("expires_in"))),
        }),
        None => Err(refused(
            cx,
            format!("CrowdStrike authentication for {tenant} returned no access token"),
            None,
        )),
    }
}

/// One tenant's authenticated client (`CrowdstrikeService`).
#[derive(Debug)]
pub struct Session<'a> {
    cx: TenantContext<'a>,
    base: &'static str,
    tokens: Arc<TokenCache>,
}

impl<'a> Session<'a> {
    /// A session with a token cache of its own, signed in at once, so a
    /// tenant that refuses the credentials fails here.
    pub async fn connect(cx: TenantContext<'a>) -> Result<Self, ConnectorError> {
        let session = Self {
            cx,
            base: base_api(cx)?,
            tokens: Arc::new(TokenCache::new()),
        };
        session
            .tokens
            .token(&cx.tenant.label, session.base, || sign_in(cx, session.base))
            .await?;
        Ok(session)
    }

    /// The cloud's API (`https://api.eu-1.crowdstrike.com`).
    pub fn base(&self) -> &'static str {
        self.base
    }

    /// Sends *method* *url* (with *body*, JSON) with the session's token
    /// and headers; a `401` gets one new token and one resend.
    async fn call(
        &self,
        method: crate::transport::Method,
        url: &str,
        body: Option<&[u8]>,
        cancel: &CancellationToken,
    ) -> Result<Answer, ConnectorError> {
        let (cx, base) = (self.cx, self.base);
        self.tokens
            .send(
                cx,
                base,
                || sign_in(cx, base),
                |token| {
                    let builder = cx
                        .http
                        .request(method.clone(), url)
                        .header("Authorization", format!("Bearer {}", token.expose()))
                        .header("Content-Type", "application/json")
                        .header("accept", "application/json");
                    match body {
                        Some(body) => builder.body(body.to_vec()),
                        None => builder,
                    }
                },
                cancel,
            )
            .await
    }

    /// Creates a correlation rule from its compiled *body*, returning its id
    /// (`create_detection_rule`: 200 and `resources[0].id`).
    pub async fn create_detection_rule(&self, body: &[u8]) -> Result<String, ConnectorError> {
        let url = format!("{}{RULES}", self.base);
        let answer = self
            .call(
                crate::transport::Method::POST,
                &url,
                Some(body),
                self.cx.cancel,
            )
            .await?;
        let tenant = &self.cx.tenant.label.tenant;
        if answer.status != 200 {
            return Err(refused(
                self.cx,
                format!(
                    "Was not able to create rule against tenant {tenant} - Error Code {}",
                    answer.status
                ),
                Some(answer.text()),
            ));
        }
        answer
            .json()
            .and_then(|body| {
                let id = body.get("resources")?;
                let Json::Array(resources) = id else {
                    return None;
                };
                resources
                    .first()?
                    .get("id")
                    .map(opentide_compile::deploy::text)
            })
            .ok_or_else(|| {
                refused(
                    self.cx,
                    "the rule id was not present in the response body".to_owned(),
                    Some(answer.text()),
                )
            })
    }

    /// Updates the rule *rule_id* with its compiled *body*, the one-rule
    /// list with the id (`update_detection_rule`: `PATCH`, 200).
    pub async fn update_detection_rule(
        &self,
        rule_id: &str,
        body: &[u8],
    ) -> Result<(), ConnectorError> {
        let url = format!("{}{RULES}", self.base);
        let answer = self
            .call(
                crate::transport::Method::PATCH,
                &url,
                Some(body),
                self.cx.cancel,
            )
            .await?;
        if answer.status == 200 {
            return Ok(());
        }
        Err(refused(
            self.cx,
            format!(
                "Was not able to update rule with id {rule_id} against tenant {} - Error Code {}",
                self.cx.tenant.label.tenant, answer.status
            ),
            Some(answer.text()),
        ))
    }

    /// Deletes the rule *rule_id* (`delete_detection_rule`: `DELETE ?ids=`,
    /// 200).
    pub async fn delete_detection_rule(&self, rule_id: &str) -> Result<(), ConnectorError> {
        let url = format!(
            "{}{RULES}?{}",
            self.base,
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([("ids", rule_id)])
                .finish()
        );
        let answer = self
            .call(crate::transport::Method::DELETE, &url, None, self.cx.cancel)
            .await?;
        if answer.status == 200 {
            return Ok(());
        }
        Err(refused(
            self.cx,
            format!(
                "Was not able to delete rule with ID {rule_id} against tenant {} - Error Code {}",
                self.cx.tenant.label.tenant, answer.status
            ),
            Some(
                "Verify API permission, and check if the rule was not already removed from the \
                 console"
                    .to_owned(),
            ),
        ))
    }

    /// Runs a CQL search (`CrowdstrikeQueryRunner.run` after the client is
    /// built): starts the query job, polls it until done, and stops it
    /// (`DELETE`) when it outlives *request*'s timeout, the tenant cancels
    /// it, or the run is cancelled.
    pub async fn search(&self, request: &QueryRequest) -> Result<QueryOutcome, ConnectorError> {
        let repository = request
            .index
            .first()
            .map_or(DEFAULT_REPOSITORY, String::as_str);
        let jobs = format!(
            "{}/humio/api/v1/repositories/{}/queryjobs",
            self.base,
            utf8_percent_encode(repository, PATH_SEGMENT)
        );
        let sent = cql_with_limit(&request.text, request.limit);
        let start = JobStart {
            query_string: &sent,
            start: request.window.start.as_millisecond(),
            end: request.window.end.as_millisecond(),
            is_live: false,
        };
        let body = serde_json::to_vec(&start)
            .map_err(|error| refused(self.cx, error.to_string(), None))?;
        let started = self
            .call(
                crate::transport::Method::POST,
                &jobs,
                Some(&body),
                self.cx.cancel,
            )
            .await?;
        let job = self.object(&started, "start the search")?;
        let job_id = job
            .get("id")
            .filter(|id| id.is_filled())
            .map(opentide_compile::deploy::text)
            .unwrap_or_default();
        let tenant = &self.cx.tenant.label.tenant;
        if job_id.is_empty() {
            return Err(refused(
                self.cx,
                format!("Next-Gen SIEM returned no search id on {tenant}"),
                None,
            ));
        }
        let status_url = format!("{jobs}/{}", utf8_percent_encode(&job_id, PATH_SEGMENT));
        let status = match self.wait(&status_url, request).await {
            Ok(status) => status,
            Err(error) => {
                self.stop(&status_url).await;
                return Err(error);
            }
        };
        let rows: Vec<Row> = match status.get("events") {
            Some(Json::Array(events)) => events
                .iter()
                .filter_map(Json::as_object)
                .map(flatten)
                .collect(),
            _ => Vec::new(),
        };
        let warnings = match status.get("messages") {
            Some(Json::Array(messages)) => messages
                .iter()
                .map(|item| match item {
                    Json::Object(object) => object
                        .get("message")
                        .map_or_else(|| crate::text::json_text(item), crate::text::json_text),
                    other => crate::text::json_text(other),
                })
                .collect(),
            _ => Vec::new(),
        };
        let kept: Vec<Row> = rows.iter().take(request.limit).cloned().collect();
        Ok(QueryOutcome {
            columns: columns_of(&kept),
            truncated: rows.len() > request.limit,
            rows: kept,
            partial: false,
            warnings,
            vendor_query_id: Some(job_id),
            sent: (sent != request.text.trim()).then_some(sent),
            language: Some("cql".to_owned()),
        })
    }

    /// Polls the job at *url* until it is done, its deadline passes, the
    /// tenant cancels it or the run is cancelled.
    async fn wait(&self, url: &str, request: &QueryRequest) -> Result<Json, ConnectorError> {
        let deadline = tokio::time::Instant::now() + request.timeout;
        let mut delay = FIRST_POLL_DELAY;
        let tenant = &self.cx.tenant.label.tenant;
        loop {
            let answer = self
                .call(crate::transport::Method::GET, url, None, self.cx.cancel)
                .await?;
            let status = self.object(&answer, "read the search")?;
            if status.get("cancelled").is_some_and(Json::is_true) {
                return Err(refused(
                    self.cx,
                    format!("the search was cancelled on {tenant}"),
                    None,
                ));
            }
            if status.get("done").is_some_and(Json::is_true) {
                return Ok(status);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ConnectorError::QueryTimedOut {
                    platform: PLATFORM.to_owned(),
                    tenant: tenant.clone(),
                    message: format!(
                        "the search did not finish within {}s on {tenant}",
                        request.timeout.as_secs_f64()
                    ),
                    detail: Some("narrow the window or raise --timeout".to_owned()),
                    timeout: request.timeout,
                });
            }
            tokio::select! {
                biased;
                () = self.cx.cancel.cancelled() => return Err(ConnectorError::Cancelled),
                () = tokio::time::sleep(delay) => {}
            }
            delay = (delay * 2).min(MAX_POLL_DELAY);
        }
    }

    /// Stops the search at *url*, which the runner no longer waits for; a
    /// failure to stop it is not the caller's error (`_stop`). It is sent
    /// even when the run was cancelled.
    async fn stop(&self, url: &str) {
        let cancel = CancellationToken::new();
        let stopping = self.call(crate::transport::Method::DELETE, url, None, &cancel);
        let _ = tokio::time::timeout(STOP_TIMEOUT, stopping).await;
    }

    /// The answer's JSON object (`_json`): an HTTP error is a refusal
    /// naming *action* (with the scope a 403 lacks), an answer that is not
    /// JSON a refusal describing it, and JSON that is not an object an
    /// empty one.
    fn object(&self, answer: &Answer, action: &str) -> Result<Json, ConnectorError> {
        let tenant = &self.cx.tenant.label.tenant;
        // A 3xx is a refusal too: a redirect the client could not follow.
        if !(200..300).contains(&answer.status) {
            let detail = if answer.status == 403 {
                Some("the API client needs the NGSIEM: Read scope".to_owned())
            } else {
                answer
                    .not_json_detail()
                    .or_else(|| Some(answer.text_head(500)).filter(|text| !text.is_empty()))
            };
            return Err(refused(
                self.cx,
                format!(
                    "Next-Gen SIEM could not {action} on {tenant} (HTTP {})",
                    answer.status
                ),
                detail,
            ));
        }
        match answer.json() {
            Some(body @ Json::Object(_)) => Ok(body),
            Some(_) => Ok(Json::Object(opentide_compile::json::Object::new())),
            None => Err(refused(
                self.cx,
                format!("Next-Gen SIEM did not answer with JSON to {action} on {tenant}"),
                answer.not_json_detail(),
            )),
        }
    }
}

/// The query job's body, in the client's key order.
#[derive(serde::Serialize)]
struct JobStart<'a> {
    #[serde(rename = "queryString")]
    query_string: &'a str,
    start: i64,
    end: i64,
    #[serde(rename = "isLive")]
    is_live: bool,
}

/// *query* with `| head(limit=limit+1)` appended, unless it has a `head` or
/// `tail` of its own (`cql_with_limit`).
pub fn cql_with_limit(query: &str, limit: usize) -> String {
    static HEAD: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    let text = query.trim();
    let has_head = HEAD
        .get_or_init(|| regex::Regex::new(r"(?i)\|\s*(?:head|tail)\s*\(").ok())
        .as_ref()
        .is_some_and(|head| head.is_match(text));
    if has_head {
        text.to_owned()
    } else {
        format!("{text}\n| head(limit={})", limit.saturating_add(1))
    }
}

/// The platform: a deployer and the CQL runner, which share each tenant's
/// token until it is due for renewal. No live validator.
#[derive(Debug, Default)]
pub struct Crowdstrike {
    tokens: Arc<TokenCache>,
}

impl Crowdstrike {
    /// A platform with no token yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// A platform whose tokens are kept in *tokens*.
    pub fn with_tokens(tokens: Arc<TokenCache>) -> Self {
        Self { tokens }
    }

    /// Signs in to the tenant now, unless a token is kept, so a tenant that
    /// refuses the credentials fails before any rule is sent; its
    /// [`Deployer`] then deploys on that token.
    ///
    /// # Errors
    ///
    /// The tenant's refusal of the credentials, or why it could not be asked.
    pub async fn sign_in(&self, cx: TenantContext<'_>) -> Result<(), ConnectorError> {
        self.sign_in_for(cx, false).await
    }

    /// [`Self::sign_in`], its refusal told as a probe tells it when *probing*
    /// ([`token_refusal`]).
    async fn sign_in_for(
        &self,
        cx: TenantContext<'_>,
        probing: bool,
    ) -> Result<(), ConnectorError> {
        let session = self.session(cx)?;
        let base = session.base;
        session
            .tokens
            .token(&cx.tenant.label, base, || sign_in_as(cx, base, probing))
            .await
            .map(|_| ())
    }

    /// The tenant's cloud and client id and secret, resolved: what a deploy's
    /// open and a connectivity probe both start with.
    fn resolve(cx: TenantContext<'_>) -> Result<(), ConnectorError> {
        base_api(cx)?;
        cx.tenant.secret("client_id")?;
        cx.tenant.secret("client_secret").map(|_| ())
    }

    /// The tenant's session on the platform's tokens; it signs in on its
    /// first call when no token is kept.
    fn session<'a>(&self, cx: TenantContext<'a>) -> Result<Session<'a>, ConnectorError> {
        Ok(Session {
            cx,
            base: base_api(cx)?,
            tokens: Arc::clone(&self.tokens),
        })
    }
}

impl Prober for Crowdstrike {
    /// Resolves the cloud and the client id and secret as a deploy does, signs
    /// in as a deploy does (`POST <api>/oauth2/token`, the token kept for
    /// later calls), then lists one correlation rule id
    /// (`GET <api>/correlation-rules/queries/rules/v1?limit=1`), a read the
    /// deploy's own scope covers. A token endpoint that answers 400, 401 or 403 is
    /// [`ConnectorError::Authentication`]; a 502, 503 or 504 is
    /// `tenant_gateway`, and any other non-201 (429, 500) `tenant_refused`: no
    /// call can follow, but the credentials are not blamed.
    fn probe<'a>(
        &'a self,
        cx: TenantContext<'a>,
    ) -> BoxFuture<'a, Result<(), crate::connector::DeployError>> {
        crate::connector::probing(async move {
            Self::resolve(cx)?;
            self.sign_in_for(cx, true).await?;
            let session = self.session(cx)?;
            let url = format!("{}{RULE_IDS}?limit=1", session.base);
            let answer = session
                .call(crate::transport::Method::GET, &url, None, cx.cancel)
                .await?;
            probe_verdict(
                PLATFORM,
                &cx.tenant.label.tenant,
                "listing the correlation rules",
                answer.status,
            )
        })
    }
}

impl Deployer for Crowdstrike {
    /// The tenant's cloud and client id and secret: nothing is sent; the
    /// first rule signs in.
    fn open<'a>(
        &'a self,
        cx: TenantContext<'a>,
    ) -> BoxFuture<'a, Result<(), crate::connector::DeployError>> {
        crate::connector::opening(async move { Self::resolve(cx) })
    }

    /// Creates (`POST`), updates or disables (`PATCH` of the compiled
    /// one-rule list) or deletes (`DELETE ?ids=`) one rule; the remote id
    /// is the created rule's, or *request*'s for an update. The tenant is
    /// signed in first (on its kept token, if any): a sign-in that fails,
    /// whatever the answer, fails the tenant, as `opentide deploy` stops it,
    /// since no rule can deploy without a token.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, crate::connector::DeployError>> {
        Box::pin(async move {
            self.sign_in(cx).await.map_err(|error| {
                let mut failed = crate::connector::DeployError::from(error);
                failed.scope = crate::connector::DeployScope::Tenant;
                failed
            })?;
            let session = self.session(cx)?;
            let remote_id = match request.operation {
                Operation::Create => Some(session.create_detection_rule(&request.body).await?),
                Operation::Update | Operation::Disable => {
                    session
                        .update_detection_rule(&request.rule_id, &request.body)
                        .await?;
                    Some(request.rule_id.clone())
                }
                Operation::Delete => {
                    session.delete_detection_rule(&request.rule_id).await?;
                    None
                }
            };
            Ok(DeployOutcome {
                events: Vec::new(),
                remote_id,
                operation: request.operation,
                warnings: Vec::new(),
            })
        })
    }
}

impl QueryRunner for Crowdstrike {
    /// A CQL search on one repository (`--index` once at most), on the
    /// tenant's kept token.
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        Box::pin(async move {
            if request.index.len() > 1 {
                return Err(refused(
                    cx,
                    "a Next-Gen SIEM search reads one repository: pass --index once".to_owned(),
                    Some(format!("got {}", request.index.join(", "))),
                ));
            }
            self.session(cx)?.search(request).await
        })
    }
}

impl Platform for Crowdstrike {
    fn id(&self) -> &'static str {
        PLATFORM
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self)
    }

    fn prober(&self) -> Option<&dyn Prober> {
        Some(self)
    }

    fn query_runner(&self) -> Option<&dyn QueryRunner> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limit_is_appended_unless_the_query_has_one() {
        assert_eq!(cql_with_limit("  x  ", 100), "x\n| head(limit=101)");
        assert_eq!(cql_with_limit("x | HEAD (5)", 1), "x | HEAD (5)");
        assert_eq!(cql_with_limit("x |tail(limit=3)", 1), "x |tail(limit=3)");
        assert_eq!(cql_with_limit("headline", 0), "headline\n| head(limit=1)");
    }
}
