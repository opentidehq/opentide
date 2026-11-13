//! SentinelOne's management API (UC-4.2, #832): `platforms/sentinel_one/
//! client.py` (`SentinelOneService`: STAR custom detection rules and
//! `validate_query`), the calls its `deployer.py` makes, and `runner.py`
//! (PowerQuery, submitted then polled until it finishes), request for
//! request. `validate query --live` checks a rule's queries with the runner,
//! for one row over the minute before now (`LiveQueryValidator`).
//!
//! Every call carries `Authorization: ApiToken <api_token>` and `Content-Type:
//! application/json`; the rule bodies are the compiled STAR rule
//! (`opentide-compile` `sentinel_one::body`), written as `json.dumps` writes
//! them.

use std::time::{Duration, Instant};

use opentide_compile::json::{Json, Object};

use crate::answer::Answer;
use crate::body::python_json;
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, LiveCheck, LiveValidator, Operation,
    Platform, QueryColumn, QueryOutcome, QueryRequest, QueryRunner, Row, TenantContext, TimeWindow,
    kql_code, utc_z,
};
use crate::error::ConnectorError;
use crate::python::python_str;
use crate::{HttpSettings, Secret};

/// The platform's identifier.
pub const PLATFORM: &str = "sentinel_one";

/// The STAR rules collection, under the tenant's `url`.
pub const RULES_PATH: &str = "/web/api/v2.1/cloud-detection/rules";
/// PowerQuery, under the tenant's `url`.
pub const QUERY_PATH: &str = "/web/api/v2.1/dv/events/pq";
/// A PowerQuery's progress, under the tenant's `url`.
pub const PING_PATH: &str = "/web/api/v2.1/dv/events/pq-ping";

/// The longest wait between two polls of a running PowerQuery.
pub const MAX_POLL_DELAY: Duration = Duration::from_secs(5);

/// The HTTP settings of a SentinelOne tenant: `TenantSession`'s, no retries.
pub fn http_settings() -> HttpSettings {
    HttpSettings::default()
}

/// Why a STAR rule call failed (`_http_errors`).
#[derive(Debug, thiserror::Error)]
pub enum SentinelOneError {
    /// HTTP 400: the console refused the rule (`invalid user input`).
    #[error("SentinelOne refused the rule (HTTP 400): {detail}")]
    Invalid {
        /// The console's answer, as text.
        detail: String,
    },
    /// HTTP 401: the token may not do this
    /// (`TideTenantConfigurationMissingPermissions`).
    #[error("SentinelOne refused the API token (HTTP 401): {detail}")]
    Unauthorized {
        /// The console's answer, as text.
        detail: String,
    },
    /// HTTP 404: the rule is not on the console.
    #[error(
        "SentinelOne has no such rule (HTTP 404): {detail}. Check in the SentinelOne console whether the rule still exists. If not, remove its sentinel_one entry from the rule's deployment state in .opentide/states/deployment/"
    )]
    NotFound {
        /// The console's answer, as text.
        detail: String,
    },
    /// Any other status (`Unforeseen error with code`).
    #[error("Unforeseen error with code [{status}]: {context}")]
    Unforeseen {
        /// The status.
        status: u16,
        /// The console's answer.
        context: String,
    },
    /// The console's answer could not be read.
    #[error("SentinelOne answered without the rule's id: {detail}")]
    Unreadable {
        /// What it answered.
        detail: String,
    },
    /// A deployment-state id that is not a number (`int(external_id)`).
    #[error("invalid literal for int() with base 10: {0:?}")]
    BadId(String),
    /// The tenant could not be reached, or the run was cancelled.
    #[error(transparent)]
    Connector(#[from] ConnectorError),
}

/// What `validate_query` concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryValidation {
    /// The query ran.
    Ran,
    /// The console refused it (HTTP 400), with its detail.
    Refused(String),
}

/// The SentinelOne connector.
#[derive(Clone, Copy, Debug, Default)]
pub struct SentinelOne;

/// The tenant's `url`, `api_token`, `account_id` and `site_id`.
struct Setup {
    url: String,
    token: Secret,
    account_id: String,
    site_id: Option<String>,
}

fn setup(cx: TenantContext<'_>) -> Result<Setup, ConnectorError> {
    let url = cx.tenant.secret("url")?.expose().to_owned();
    let token = cx.tenant.secret("api_token")?.clone();
    let account_id = cx.tenant.secret("account_id")?.expose().to_owned();
    // `if site_id := setup.site_id`: an empty or zero site is none.
    let site_id = cx
        .tenant
        .setup
        .get("site_id")
        .and_then(crate::Credential::secret)
        .map(|secret| secret.expose().to_owned())
        .filter(|site| !site.is_empty() && site != "0");
    Ok(Setup {
        url,
        token,
        account_id,
        site_id,
    })
}

impl SentinelOne {
    /// A call with the session's headers; *body* is sent as given.
    async fn call(
        cx: TenantContext<'_>,
        setup: &Setup,
        method: reqwest::Method,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Answer, ConnectorError> {
        let mut builder = cx
            .http
            .request(method, url)
            .header(
                "Authorization",
                format!("ApiToken {}", setup.token.expose()),
            )
            .header("Content-Type", "application/json");
        if let Some(body) = body {
            builder = builder.body(body);
        }
        crate::answer::exchange(cx, builder).await
    }

    /// Creates the STAR rule *body*, or replaces rule *rule_id* with it
    /// (`create_update_detection_rule`); returns the rule's id.
    pub async fn create_update_rule(
        &self,
        cx: TenantContext<'_>,
        body: &Json,
        rule_id: Option<i64>,
    ) -> Result<i64, SentinelOneError> {
        let setup = setup(cx)?;
        let bytes = write(cx, body)?;
        let mut url = format!("{}{RULES_PATH}", setup.url);
        let method = match rule_id {
            Some(id) => {
                url.push_str(&format!("/{id}"));
                reqwest::Method::PUT
            }
            None => reqwest::Method::POST,
        };
        let answer = Self::call(cx, &setup, method, &url, Some(bytes)).await?;
        if answer.status == 200 {
            let id = answer
                .json()
                .as_ref()
                .and_then(|body| body.get("data"))
                .and_then(|data| data.get("id"))
                .and_then(|id| match id {
                    Json::Str(text) => text.trim().parse::<i64>().ok(),
                    Json::Int(id) => Some(*id),
                    _ => None,
                });
            return id.ok_or_else(|| SentinelOneError::Unreadable {
                detail: answer.text(),
            });
        }
        Err(http_error(&answer))
    }

    /// Disables rule *rule_id* (`disable_detection_rule`).
    pub async fn disable_rule(
        &self,
        cx: TenantContext<'_>,
        rule_id: i64,
    ) -> Result<(), SentinelOneError> {
        self.by_filter(cx, reqwest::Method::PUT, rule_id).await
    }

    /// Deletes rule *rule_id* (`delete_detection_rule`).
    pub async fn delete_rule(
        &self,
        cx: TenantContext<'_>,
        rule_id: i64,
    ) -> Result<(), SentinelOneError> {
        self.by_filter(cx, reqwest::Method::DELETE, rule_id).await
    }

    async fn by_filter(
        &self,
        cx: TenantContext<'_>,
        method: reqwest::Method,
        rule_id: i64,
    ) -> Result<(), SentinelOneError> {
        let setup = setup(cx)?;
        let mut ids = Object::new();
        ids.insert("ids".into(), Json::Array(vec![Json::Int(rule_id)]));
        let mut filter = Object::new();
        filter.insert("filter".into(), Json::Object(ids));
        let bytes = write(cx, &Json::Object(filter))?;
        let url = format!("{}{RULES_PATH}", setup.url);
        let answer = Self::call(cx, &setup, method, &url, Some(bytes)).await?;
        if answer.status == 200 {
            return Ok(());
        }
        Err(http_error(&answer))
    }

    /// Runs *query* as a PowerQuery over the minute before *now*
    /// (`validate_query`): whether the console can run it.
    pub async fn validate_query(
        &self,
        cx: TenantContext<'_>,
        query: &str,
        now: jiff::Timestamp,
    ) -> Result<QueryValidation, SentinelOneError> {
        let setup = setup(cx)?;
        let window = TimeWindow::check(now);
        let mut body = Object::new();
        body.insert("accountIds".into(), Json::Str(setup.account_id.clone()));
        if let Some(site) = &setup.site_id {
            body.insert("site_id".into(), Json::Str(site.clone()));
        }
        body.insert("query".into(), Json::Str(query.to_owned()));
        body.insert("toDate".into(), Json::Str(utc_z(window.end)));
        body.insert("fromDate".into(), Json::Str(utc_z(window.start)));
        let bytes =
            python_json_indented(&Json::Object(body)).map_err(|error| ConnectorError::Setup {
                platform: PLATFORM.into(),
                tenant: cx.tenant.label.tenant.clone(),
                message: format!("the query cannot be written: {error}"),
            })?;
        let url = format!("{}{QUERY_PATH}", setup.url);
        let answer = Self::call(cx, &setup, reqwest::Method::POST, &url, Some(bytes)).await?;
        match answer.status {
            200 => Ok(QueryValidation::Ran),
            400 => {
                let body = answer.json().unwrap_or(Json::Null);
                let detail = body
                    .get("errors")
                    .and_then(|errors| match errors {
                        Json::Array(items) => items.first(),
                        _ => None,
                    })
                    .and_then(|error| error.get("detail"))
                    .map_or_else(|| python_str(&body), python_str);
                Ok(QueryValidation::Refused(detail))
            }
            status => Err(SentinelOneError::Unforeseen {
                status,
                context: answer
                    .json()
                    .map_or_else(|| answer.text(), |b| python_str(&b)),
            }),
        }
    }

    /// Runs a PowerQuery over the request's window and polls it until it
    /// finishes (`SentinelOneQueryRunner.run`).
    pub async fn run(
        &self,
        cx: TenantContext<'_>,
        request: &QueryRequest,
    ) -> Result<QueryOutcome, ConnectorError> {
        let tenant = cx.tenant.label.tenant.clone();
        let setup = setup(cx)?;
        let sent = powerquery_with_limit(&request.text, request.limit);
        let mut body = Object::new();
        body.insert("query".into(), Json::Str(sent.clone()));
        body.insert("fromDate".into(), Json::Str(utc_z(request.window.start)));
        body.insert("toDate".into(), Json::Str(utc_z(request.window.end)));
        body.insert(
            "limit".into(),
            Json::Int(i64::try_from(request.limit).unwrap_or(i64::MAX - 1) + 1),
        );
        body.insert(
            "accountIds".into(),
            Json::Array(vec![Json::Str(setup.account_id.clone())]),
        );
        if let Some(site) = &setup.site_id {
            body.insert("siteIds".into(), Json::Array(vec![Json::Str(site.clone())]));
        }
        let bytes = write(cx, &Json::Object(body))?;
        let url = format!("{}{QUERY_PATH}", setup.url);
        // A timeout too long to add to the clock never comes.
        let deadline = Instant::now().checked_add(request.timeout);
        let answer = Self::call(cx, &setup, reqwest::Method::POST, &url, Some(bytes)).await?;
        let mut data = data(&answer, &tenant)?;
        let query_id = data
            .get("queryId")
            .filter(|id| id.truthy())
            .map(python_str)
            .filter(|id| !id.is_empty());
        let ping = format!("{}{PING_PATH}", setup.url);
        let mut delay = Duration::from_millis(500);
        while !finished(&data, &tenant)? {
            let Some(id) = &query_id else {
                return Err(ConnectorError::refused(
                    PLATFORM,
                    &tenant,
                    format!("SentinelOne returned no query id on {tenant}"),
                    None,
                ));
            };
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(ConnectorError::QueryTimedOut {
                    platform: PLATFORM.into(),
                    tenant: tenant.clone(),
                    message: format!(
                        "the PowerQuery did not finish within {}s on {tenant}",
                        seconds_text(request.timeout)
                    ),
                    detail: Some("narrow the window or raise --timeout".into()),
                    timeout: request.timeout,
                });
            }
            tokio::select! {
                () = cx.cancel.cancelled() => return Err(ConnectorError::Cancelled),
                () = tokio::time::sleep(delay) => {}
            }
            delay = (delay * 2).min(MAX_POLL_DELAY);
            let url = format!(
                "{ping}?{}",
                crate::encode::urlencode([("queryId", id.as_str())])
            );
            let answer = Self::call(cx, &setup, reqwest::Method::GET, &url, None).await?;
            data = self::data(&answer, &tenant)?;
        }
        let names: Vec<String> = match data.get("columns") {
            Some(Json::Array(columns)) => columns.iter().map(column_name).collect(),
            _ => Vec::new(),
        };
        let rows: Vec<Row> = match data.get("data") {
            Some(Json::Array(rows)) => rows
                .iter()
                .filter_map(|row| match row {
                    Json::Array(values) => Some(
                        names
                            .iter()
                            .cloned()
                            .zip(values.iter().cloned())
                            .collect::<Object>(),
                    ),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        let warnings = match data.get("recommendations") {
            Some(Json::Array(items)) => items
                .iter()
                .filter(|item| item.truthy())
                .map(python_str)
                .collect(),
            _ => Vec::new(),
        };
        let truncated = rows.len() > request.limit;
        Ok(QueryOutcome {
            columns: names.into_iter().map(QueryColumn::named).collect(),
            rows: rows.into_iter().take(request.limit).collect(),
            truncated,
            partial: false,
            warnings,
            vendor_query_id: query_id,
            sent: (sent != request.text.trim()).then_some(sent),
            language: Some("powerquery".into()),
        })
    }

    /// `validate query --live`'s check of one query: one row over the
    /// request's window (`QueryRunner.check`).
    pub async fn check(
        &self,
        cx: TenantContext<'_>,
        request: &QueryRequest,
    ) -> Result<QueryOutcome, ConnectorError> {
        self.run(cx, &request.for_check()).await
    }
}

/// `{request.timeout:g}`.
fn seconds_text(timeout: Duration) -> String {
    let seconds = timeout.as_secs_f64();
    if seconds.fract() == 0.0 && seconds < 1e16 {
        format!("{}", timeout.as_secs())
    } else {
        format!("{seconds}")
    }
}

/// *value* as `json.dumps` writes it.
fn write(cx: TenantContext<'_>, value: &Json) -> Result<Vec<u8>, ConnectorError> {
    python_json(value).map_err(|error| ConnectorError::Setup {
        platform: PLATFORM.into(),
        tenant: cx.tenant.label.tenant.clone(),
        message: format!("the request body cannot be written: {error}"),
    })
}

/// *value* as `json.dumps(value, indent=4)` writes it.
fn python_json_indented(value: &Json) -> serde_json::Result<Vec<u8>> {
    use serde::Serialize as _;
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, Indented::default());
    value.serialize(&mut serializer)?;
    Ok(out)
}

/// `json.dumps(indent=4)`'s layout: serde_json's pretty printer, four
/// spaces, every character outside ASCII escaped.
struct Indented<'a>(serde_json::ser::PrettyFormatter<'a>);

impl Default for Indented<'_> {
    fn default() -> Self {
        Self(serde_json::ser::PrettyFormatter::with_indent(b"    "))
    }
}

impl serde_json::ser::Formatter for Indented<'_> {
    fn begin_array<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.begin_array(w)
    }
    fn end_array<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.end_array(w)
    }
    fn begin_array_value<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        self.0.begin_array_value(w, first)
    }
    fn end_array_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.end_array_value(w)
    }
    fn begin_object<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.begin_object(w)
    }
    fn end_object<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.end_object(w)
    }
    fn begin_object_key<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        self.0.begin_object_key(w, first)
    }
    fn begin_object_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.begin_object_value(w)
    }
    fn end_object_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.end_object_value(w)
    }
    fn write_string_fragment<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        fragment: &str,
    ) -> std::io::Result<()> {
        crate::body::PythonJson.write_string_fragment(w, fragment)
    }
    fn write_char_escape<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        escape: serde_json::ser::CharEscape,
    ) -> std::io::Result<()> {
        crate::body::PythonJson.write_char_escape(w, escape)
    }
}

/// The error of a STAR rule call that did not answer 200 (`_http_errors`).
fn http_error(answer: &Answer) -> SentinelOneError {
    let detail = answer.text();
    match answer.status {
        400 => SentinelOneError::Invalid { detail },
        401 => SentinelOneError::Unauthorized { detail },
        404 => SentinelOneError::NotFound { detail },
        status => SentinelOneError::Unforeseen {
            status,
            context: answer.json().map_or(detail, |body| python_str(&body)),
        },
    }
}

/// `powerquery_with_limit`: `| limit limit+1` on a line of its own, unless
/// the query has a `limit` stage outside its strings and comments.
pub fn powerquery_with_limit(query: &str, limit: usize) -> String {
    static STAGE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    let text = query.trim();
    let has_stage = STAGE
        .get_or_init(|| regex::Regex::new(r"(?i)\|\s*limit\s+\d+").ok())
        .as_ref()
        .is_some_and(|stage| stage.is_match(&kql_code(text)));
    if has_stage {
        return text.to_owned();
    }
    format!("{text}\n| limit {}", limit.saturating_add(1))
}

/// Whether a PowerQuery is done; a failed one is a refusal (`_finished`).
fn finished(data: &Json, tenant: &str) -> Result<bool, ConnectorError> {
    let status = data
        .get("status")
        .map(python_str)
        .unwrap_or_default()
        .to_uppercase();
    if ["FAILED", "FAILED_CLIENT", "TIMED_OUT", "CANCELLED"].contains(&status.as_str()) {
        let detail = data
            .get("responseError")
            .filter(|value| value.truthy())
            .or_else(|| data.get("error"))
            .filter(|value| value.truthy())
            .map(python_str)
            .filter(|text| !text.is_empty());
        return Err(ConnectorError::refused(
            PLATFORM,
            tenant,
            format!("the PowerQuery ended {}", status.to_lowercase()),
            detail,
        ));
    }
    Ok(status == "FINISHED")
}

/// The `data` of a PowerQuery answer, or the refusal it is (`_data`).
fn data(answer: &Answer, tenant: &str) -> Result<Json, ConnectorError> {
    let Some(body) = answer.json() else {
        return Err(ConnectorError::refused(
            PLATFORM,
            tenant,
            format!("SentinelOne did not answer the PowerQuery on {tenant} with JSON"),
            answer.not_json_detail(),
        ));
    };
    if answer.status != 200 {
        let detail = body
            .get("errors")
            .and_then(|errors| match errors {
                Json::Array(items) => items.first().filter(|first| first.as_object().is_some()),
                _ => None,
            })
            .and_then(|error| {
                error
                    .get("detail")
                    .filter(|value| value.truthy())
                    .or_else(|| error.get("title"))
            })
            .filter(|value| value.truthy())
            .map(python_str)
            .filter(|text| !text.is_empty());
        let text: String = answer.text().chars().take(500).collect();
        return Err(ConnectorError::refused(
            PLATFORM,
            tenant,
            format!(
                "SentinelOne refused the PowerQuery on {tenant} (HTTP {})",
                answer.status
            ),
            detail.or((!text.is_empty()).then_some(text)),
        ));
    }
    Ok(match body.get("data") {
        Some(data @ Json::Object(_)) => data.clone(),
        _ => Json::Object(Object::new()),
    })
}

/// A column's name (`_column_name`).
fn column_name(column: &Json) -> String {
    match column {
        Json::Object(_) => column
            .get("name")
            .filter(|value| value.truthy())
            .or_else(|| column.get("title"))
            .filter(|value| value.truthy())
            .map(python_str)
            .unwrap_or_default(),
        other => python_str(other),
    }
}

/// `int(external_id)` of a deployment-state id.
pub fn rule_id(text: &str) -> Result<i64, SentinelOneError> {
    text.trim()
        .parse::<i64>()
        .map_err(|_| SentinelOneError::BadId(text.to_owned()))
}

impl Deployer for SentinelOne {
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        Box::pin(async move {
            let address = || {
                cx.tenant
                    .secret("url")
                    .map(|url| url.expose().to_owned())
                    .unwrap_or_default()
            };
            let answer = |error: SentinelOneError| match error {
                SentinelOneError::Connector(error) => error,
                other => ConnectorError::Answer {
                    platform: PLATFORM.into(),
                    tenant: cx.tenant.label.tenant.clone(),
                    address: address(),
                    reason: other.to_string(),
                },
            };
            let body = || -> Result<Json, ConnectorError> {
                serde_json::from_slice(&request.body).map_err(|error| ConnectorError::Setup {
                    platform: PLATFORM.into(),
                    tenant: cx.tenant.label.tenant.clone(),
                    message: format!("the compiled rule is not JSON: {error}"),
                })
            };
            let remote_id = match request.operation {
                Operation::Create => Some(
                    self.create_update_rule(cx, &body()?, None)
                        .await
                        .map_err(answer)?
                        .to_string(),
                ),
                // A disabled rule is the rule with `status` "Disabled".
                Operation::Update | Operation::Disable => {
                    let id = rule_id(&request.rule_id).map_err(answer)?;
                    Some(
                        self.create_update_rule(cx, &body()?, Some(id))
                            .await
                            .map_err(answer)?
                            .to_string(),
                    )
                }
                Operation::Delete => {
                    let id = rule_id(&request.rule_id).map_err(answer)?;
                    self.delete_rule(cx, id).await.map_err(answer)?;
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

impl QueryRunner for SentinelOne {
    /// A PowerQuery over the request's window, polled until it finishes.
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        Box::pin(async move { SentinelOne::run(self, cx, request).await })
    }
}

impl LiveValidator for SentinelOne {
    /// The runner's check: one row over the request's window, as Python's
    /// `LiveQueryValidator` asks it.
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        Box::pin(async move {
            let result = self.check(cx, request).await?;
            Ok(LiveCheck {
                result: Some(result),
                errors: Vec::new(),
                warnings: Vec::new(),
            })
        })
    }
}

impl Platform for SentinelOne {
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
mod tests {
    use super::*;

    #[test]
    fn the_limit_stage_is_read_past_strings_and_comments() {
        assert_eq!(powerquery_with_limit(" a | LIMIT 5 ", 100), "a | LIMIT 5");
        assert_eq!(
            powerquery_with_limit("a = '| limit 5' // | limit 3", 100),
            "a = '| limit 5' // | limit 3\n| limit 101"
        );
        let mut body = Object::new();
        body.insert("accountIds".into(), Json::Str("42".into()));
        body.insert("q".into(), Json::Str("é".into()));
        body.insert("ids".into(), Json::Array(vec![]));
        let text = python_json_indented(&Json::Object(body)).unwrap_or_default();
        assert_eq!(
            String::from_utf8(text).unwrap_or_default(),
            "{\n    \"accountIds\": \"42\",\n    \"q\": \"\\u00e9\",\n    \"ids\": []\n}"
        );
        assert!(matches!(rule_id("x1"), Err(SentinelOneError::BadId(_))));
    }
}
