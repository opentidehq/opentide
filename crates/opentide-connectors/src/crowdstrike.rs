//! CrowdStrike Falcon (UC-4.2, #832): the correlation rules a deploy sends
//! and the Next-Gen SIEM (LogScale) query jobs `opentide query` runs.
//!
//! A port of `platforms/crowdstrike/client.py` (`CrowdstrikeService`: the
//! OAuth2 client-credentials token, then create, update and delete),
//! `deployer.py` (one token per tenant for a run, then one request per rule)
//! and `runner.py` (a query job started, polled until done and stopped when
//! the runner stops waiting for it), request for request. CrowdStrike has no
//! live validation: the platform has no [`crate::connector::LiveValidator`]
//! (`supported: False`).
//!
//! The rule bodies are `opentide-compile`'s (`crowdstrike::compile`), as
//! bytes: a create's correlation rule, an update's (or a disable's) one-rule
//! list with the id.

use std::collections::BTreeMap;
use std::time::Duration;

use opentide_compile::Json;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::answer::Answer;
use crate::body::python_json;
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, Operation, Platform, QueryOutcome,
    QueryRequest, QueryRunner, Row, TenantContext, columns_of, flatten,
};
use crate::error::ConnectorError;
use crate::http::HttpSettings;
use crate::{Secret, TenantLabel, encode};

/// The platform's identifier.
pub const PLATFORM: &str = "crowdstrike";

/// The repository a search reads when `--index` names none: every event
/// Falcon holds.
pub const DEFAULT_REPOSITORY: &str = "search-all";

/// The correlation rules endpoint, after the cloud's API.
const RULES: &str = "/correlation-rules/entities/rules/v1";

/// The first wait between two polls of a search, doubled up to
/// [`MAX_POLL_DELAY`].
const FIRST_POLL_DELAY: Duration = Duration::from_millis(500);
/// The longest wait between two polls.
const MAX_POLL_DELAY: Duration = Duration::from_secs(5);
/// How long stopping a search may take once the runner gave up on it.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// How a CrowdStrike tenant is reached when nothing else says: `requests`'
/// 120 s and no retries (the client mounts no retrying adapter).
pub fn http_defaults() -> HttpSettings {
    HttpSettings::default()
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
    builder: reqwest::RequestBuilder,
    cx: TenantContext<'_>,
) -> Result<reqwest::Request, ConnectorError> {
    builder.build().map_err(|error| ConnectorError::Setup {
        platform: PLATFORM.to_owned(),
        tenant: cx.tenant.label.tenant.clone(),
        message: crate::error::describe(error),
    })
}

/// One tenant's authenticated client (`CrowdstrikeService`).
#[derive(Debug)]
pub struct Session<'a> {
    cx: TenantContext<'a>,
    base: &'static str,
    token: Secret,
}

impl<'a> Session<'a> {
    /// Authenticates with the tenant's `client_id` and `client_secret`
    /// (`_get_access_token`: a form `POST` to `/oauth2/token`, answered 201
    /// with an `access_token`).
    pub async fn connect(cx: TenantContext<'a>) -> Result<Self, ConnectorError> {
        let base = base_api(cx)?;
        let client_id = cx.tenant.secret("client_id")?;
        let client_secret = cx.tenant.secret("client_secret")?;
        let form = encode::urlencode([
            ("client_id", client_id.expose()),
            ("client_secret", client_secret.expose()),
        ]);
        let request = build(
            cx.http
                .request(reqwest::Method::POST, &format!("{base}/oauth2/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(form),
            cx,
        )?;
        let answer = Answer::fetch(cx.http, request, cx.cancel).await?;
        let tenant = &cx.tenant.label.tenant;
        if answer.status != 201 {
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
        let token = answer
            .json()
            .and_then(|body| {
                body.get("access_token")
                    .and_then(Json::as_str)
                    .map(str::to_owned)
            })
            .filter(|token| !token.is_empty());
        match token {
            Some(token) => Ok(Self {
                cx,
                base,
                token: Secret::new(token),
            }),
            None => Err(refused(
                cx,
                format!("CrowdStrike authentication for {tenant} returned no access token"),
                None,
            )),
        }
    }

    /// The cloud's API (`https://api.eu-1.crowdstrike.com`).
    pub fn base(&self) -> &'static str {
        self.base
    }

    /// A request with the session's headers.
    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        self.cx
            .http
            .request(method, url)
            .header("Authorization", format!("Bearer {}", self.token.expose()))
            .header("Content-Type", "application/json")
            .header("accept", "application/json")
    }

    async fn send(
        &self,
        builder: reqwest::RequestBuilder,
        cancel: &CancellationToken,
    ) -> Result<Answer, ConnectorError> {
        Answer::fetch(self.cx.http, build(builder, self.cx)?, cancel).await
    }

    /// Creates a correlation rule from its compiled *body*, returning its id
    /// (`create_detection_rule`: 200 and `resources[0].id`).
    pub async fn create_detection_rule(&self, body: &[u8]) -> Result<String, ConnectorError> {
        let url = format!("{}{RULES}", self.base);
        let answer = self
            .send(
                self.request(reqwest::Method::POST, &url)
                    .body(body.to_vec()),
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
            .send(
                self.request(reqwest::Method::PATCH, &url)
                    .body(body.to_vec()),
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
            encode::urlencode([("ids", rule_id)])
        );
        let answer = self
            .send(self.request(reqwest::Method::DELETE, &url), self.cx.cancel)
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
            encode::segment(repository)
        );
        let sent = cql_with_limit(&request.text, request.limit);
        let start = JobStart {
            query_string: &sent,
            start: request.window.start.as_millisecond(),
            end: request.window.end.as_millisecond(),
            is_live: false,
        };
        let body =
            python_json(&start).map_err(|error| refused(self.cx, error.to_string(), None))?;
        let started = self
            .send(
                self.request(reqwest::Method::POST, &jobs).body(body),
                self.cx.cancel,
            )
            .await?;
        let job = self.object(&started, "start the search")?;
        let job_id = job
            .get("id")
            .filter(|id| id.truthy())
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
        let status_url = format!("{jobs}/{}", encode::segment(&job_id));
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
                        .map_or_else(|| python_text(item), python_text),
                    other => python_text(other),
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
                .send(self.request(reqwest::Method::GET, url), self.cx.cancel)
                .await?;
            let status = self.object(&answer, "read the search")?;
            if status.get("cancelled").is_some_and(Json::truthy) {
                return Err(refused(
                    self.cx,
                    format!("the search was cancelled on {tenant}"),
                    None,
                ));
            }
            if status.get("done").is_some_and(Json::truthy) {
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
    /// even when the run was cancelled, so its own token is fresh.
    async fn stop(&self, url: &str) {
        let cancel = CancellationToken::new();
        let stopping = self.send(self.request(reqwest::Method::DELETE, url), &cancel);
        let _ = tokio::time::timeout(STOP_TIMEOUT, stopping).await;
    }

    /// The answer's JSON object (`_json`): an HTTP error is a refusal
    /// naming *action* (with the scope a 403 lacks), an answer that is not
    /// JSON a refusal describing it, and JSON that is not an object an
    /// empty one.
    fn object(&self, answer: &Answer, action: &str) -> Result<Json, ConnectorError> {
        let tenant = &self.cx.tenant.label.tenant;
        if answer.status >= 400 {
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

/// A value as `str()` writes it: a string as it is, anything else as JSON.
fn python_text(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        other => other.to_compact(),
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

/// The platform: a deployer that authenticates once per tenant for the run,
/// and the CQL runner. No live validator.
#[derive(Debug, Default)]
pub struct Crowdstrike {
    /// The token of each tenant the deployer reached in this run.
    tokens: Mutex<BTreeMap<TenantLabel, Secret>>,
}

impl Crowdstrike {
    /// A platform with no token yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The tenant's session: its token from earlier in the run, else a new one.
    async fn session<'a>(&self, cx: TenantContext<'a>) -> Result<Session<'a>, ConnectorError> {
        let mut tokens = self.tokens.lock().await;
        if let Some(token) = tokens.get(&cx.tenant.label) {
            return Ok(Session {
                cx,
                base: base_api(cx)?,
                token: token.clone(),
            });
        }
        let session = Session::connect(cx).await?;
        tokens.insert(cx.tenant.label.clone(), session.token.clone());
        Ok(session)
    }
}

impl Deployer for Crowdstrike {
    /// Creates (`POST`), updates or disables (`PATCH` of the compiled
    /// one-rule list) or deletes (`DELETE ?ids=`) one rule; the remote id
    /// is the created rule's, or *request*'s for an update.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        Box::pin(async move {
            let session = self.session(cx).await?;
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
                remote_id,
                operation: request.operation,
            })
        })
    }
}

impl QueryRunner for Crowdstrike {
    /// A CQL search on one repository (`--index` once at most), with a
    /// token of its own, as each Python run authenticates afresh.
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
            let session = Session::connect(cx).await?;
            session.search(request).await
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
