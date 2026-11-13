//! Carbon Black Cloud (UC-4.3, #833): what `platforms/carbon_black/` sends
//! through cbc_sdk, request for request: the watchlist reports its
//! `deployer.py` writes (`_deploy_to_org`), `runner.py`'s process searches
//! (`opentide query`) and its `search_validation` check (`validate query
//! --live`).
//!
//! Every call carries `X-Auth-Token: <token>`; a body is JSON with its keys
//! sorted (`json.dumps(body, sort_keys=True)`) and `Content-Type:
//! application/json`. A search is validated, started as a job, polled every
//! half second until every searcher completed (or the timeout passed), then
//! read in pages. An error status is the SDK's exception, worded as it is.

use std::time::{Duration, Instant};

use opentide_compile::json::Json;
use serde_json::{Map, Value};

use crate::answer::Answer;
use crate::body::python_json;
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, LiveCheck, LiveValidator, Operation,
    Platform, QueryOutcome, QueryRequest, QueryRunner, Row, TenantContext, columns_of, flatten,
    utc_z,
};
use crate::error::ConnectorError;
use crate::retry::RetryPolicy;
use crate::{HttpSettings, Secret};

/// The platform's identifier.
pub const PLATFORM: &str = "carbon_black_cloud";

/// How long between two polls of a running search (`time.sleep(.5)`).
pub const POLL_DELAY: Duration = Duration::from_millis(500);

/// The rows a search job is created for (`args["rows"] = 10000`).
pub const JOB_ROWS: i64 = 10_000;

/// The HTTP settings of a Carbon Black Cloud tenant: *timeout* on each
/// request, and the SDK's `Retry(total=5, status_forcelist=[502, 504],
/// backoff_factor=0.5)` with urllib3's default methods.
pub fn http_settings(timeout: Duration) -> HttpSettings {
    HttpSettings {
        timeout,
        retry: RetryPolicy::urllib3(
            5,
            0.5,
            &[502, 504],
            &["DELETE", "GET", "HEAD", "OPTIONS", "PUT", "TRACE"],
        ),
        ..HttpSettings::default()
    }
}

/// An error status as the SDK's exception (`http_request`): its class and
/// its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkError {
    /// HTTP 401 (`UnauthorizedError`).
    Unauthorized(String),
    /// Any other error status (`ServerError`, `ObjectNotFoundError`,
    /// `QuerySyntaxError`, `ClientError`): an `ApiError`.
    Api(String),
}

impl SdkError {
    /// The exception's `str`.
    pub fn text(&self) -> &str {
        match self {
            Self::Unauthorized(text) | Self::Api(text) => text,
        }
    }
}

/// The SDK's exception for *answer* to `method uri`, or `None` for a 2xx
/// or 3xx.
fn sdk_error(method: &str, uri: &str, answer: &Answer) -> Option<SdkError> {
    let status = answer.status;
    if status < 400 {
        return None;
    }
    let text = answer.text();
    Some(if status >= 500 {
        let details = if text.is_empty() {
            " (No further information provided)".to_owned()
        } else {
            format!(" ({text})")
        };
        SdkError::Api(format!(
            "Received error code {status} from API <{uri}>{details}"
        ))
    } else if status == 404 {
        let mut message = format!("Received 404 (Object Not Found) for {uri}");
        if !text.is_empty() {
            message.push_str(&format!(": {text}"));
        }
        SdkError::Api(message)
    } else if status == 401 {
        SdkError::Unauthorized(if text.is_empty() {
            format!("Unauthorized (Check API creds): attempted to {method} {uri}")
        } else {
            format!("Check your API Credentials: {text}")
        })
    } else if status == 400
        && answer
            .json()
            .and_then(|body| body.get("reason").cloned())
            .is_some_and(|reason| reason.as_str() == Some("query_malformed_syntax"))
    {
        let mut message = format!("Received query syntax error for {uri}");
        if !text.is_empty() {
            message.push_str(&format!(": {text}"));
        }
        SdkError::Api(message)
    } else if text.is_empty() {
        SdkError::Api(format!(
            "Received error code {status} from API (No further information provided)"
        ))
    } else {
        SdkError::Api(format!("Received error code {status} from API: {text}"))
    })
}

/// What a deploy of one rule does to its watchlist report
/// (`_deploy_to_org`): the fields the deployer worked out from the rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportDeploy {
    /// The rule's UUID: its IOC's id.
    pub uuid: String,
    /// The rule's name, trimmed: its own report's title.
    pub name: String,
    /// The rule's description, trimmed.
    pub description: String,
    /// The block's query; new lines become spaces in the IOC.
    pub query: String,
    /// `true` unless the status disables or deletes the rule.
    pub deployment: bool,
    /// The report's tags: the status, the detection model and its
    /// techniques, the block's tags.
    pub tags: Vec<String>,
    /// The report's severity (`SEVERITY_MAPPING`).
    pub severity: i64,
    /// The watchlist the report is in (the block's, else the tenant's).
    pub watchlist: String,
    /// The report the IOC goes to (the block's `report`, else the rule's
    /// name).
    pub report: String,
    /// The time the SDK stamps a built or updated report with
    /// (`int(time.time())`).
    pub now: i64,
}

/// What the deploy did to the report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportChange {
    /// A new report, added to the watchlist.
    Created,
    /// The report's IOC replaced (or added) and the report updated.
    Updated,
    /// The rule's IOC taken out of a shared report, which keeps others.
    IocRemoved,
    /// The report deleted.
    Deleted,
    /// Nothing to retire: no report of that title.
    Absent,
}

/// The Carbon Black Cloud connector.
#[derive(Debug, Default)]
pub struct CarbonBlack;

/// The tenant's base URL and token.
struct Org {
    server: String,
    key: String,
    token: Secret,
}

impl Org {
    fn of(cx: TenantContext<'_>) -> Result<Self, ConnectorError> {
        Ok(Self {
            server: cx
                .tenant
                .secret("url")?
                .expose()
                .trim_end_matches('/')
                .to_owned(),
            key: cx.tenant.secret("org_key")?.expose().to_owned(),
            token: cx.tenant.secret("token")?.clone(),
        })
    }
}

impl CarbonBlack {
    /// One request (`api_json_request`): the answer, or the SDK's
    /// exception for an error status.
    async fn call(
        cx: TenantContext<'_>,
        org: &Org,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Result<Answer, SdkError>, ConnectorError> {
        let uri = format!("{}{path}", org.server);
        let mut builder = cx
            .http
            .request(method.clone(), &uri)
            .header("X-Auth-Token", org.token.expose());
        if let Some(body) = body {
            let bytes = python_json(body).map_err(|error| ConnectorError::Setup {
                platform: PLATFORM.into(),
                tenant: cx.tenant.label.tenant.clone(),
                message: format!("the request body cannot be written: {error}"),
            })?;
            builder = builder
                .header("Content-Type", "application/json")
                .body(bytes);
        }
        let answer = crate::answer::exchange(cx, builder).await?;
        Ok(match sdk_error(method.as_str(), &uri, &answer) {
            Some(error) => Err(error),
            None => Ok(answer),
        })
    }

    /// `get_object`, `post_object`, `put_object`: the answer's JSON (sorted
    /// keys; `None` for a 204), or the SDK's exception.
    async fn json(
        cx: TenantContext<'_>,
        org: &Org,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Result<Option<Value>, SdkError>, ConnectorError> {
        let answer = match Self::call(cx, org, method, path, body).await? {
            Ok(answer) => answer,
            Err(error) => return Ok(Err(error)),
        };
        if answer.status == 204 {
            return Ok(Ok(None));
        }
        match serde_json::from_slice::<Value>(&answer.body) {
            Ok(value) => Ok(Ok(Some(value))),
            Err(_) => Ok(Err(SdkError::Api(format!(
                "Received error code {} from API (Cannot parse response as JSON: {:?})",
                answer.status,
                String::from_utf8_lossy(&answer.body)
            )))),
        }
    }

    /// `get_object` in a deploy: the JSON, or the SDK's exception raised.
    async fn get(cx: TenantContext<'_>, org: &Org, path: &str) -> Result<Value, ConnectorError> {
        match Self::json(cx, org, reqwest::Method::GET, path, None).await? {
            Ok(value) => Ok(value.unwrap_or(Value::Null)),
            Err(error) => Err(Self::refused(cx, &error)),
        }
    }

    /// A deploy call the tenant refused: the SDK's exception, raised out of
    /// the deployer.
    fn refused(cx: TenantContext<'_>, error: &SdkError) -> ConnectorError {
        match error {
            SdkError::Unauthorized(text) => {
                ConnectorError::authentication(PLATFORM, &cx.tenant.label.tenant, text.clone())
            }
            SdkError::Api(text) => {
                ConnectorError::refused(PLATFORM, &cx.tenant.label.tenant, text.clone(), None)
            }
        }
    }

    /// Writes the rule's IOC to its watchlist report, or retires it
    /// (`_deploy_to_org`).
    pub async fn deploy_report(
        &self,
        cx: TenantContext<'_>,
        plan: &ReportDeploy,
    ) -> Result<ReportChange, ConnectorError> {
        let org = Org::of(cx)?;
        let watchlists_path = format!("/threathunter/watchlistmgr/v3/orgs/{}/watchlists", org.key);
        let reports_path = format!("/threathunter/watchlistmgr/v3/orgs/{}/reports", org.key);
        // `watchlist_list or []` counts the watchlists, then the loop reads them.
        Self::get(cx, &org, &watchlists_path).await?;
        let listed = Self::get(cx, &org, &watchlists_path).await?;
        let mut watchlist: Option<Map<String, Value>> = None;
        for item in listed
            .get("results")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if item.get("name").and_then(Value::as_str) == Some(plan.watchlist.as_str())
                && let Some(object) = item.as_object()
            {
                watchlist = Some(object.clone());
            }
        }
        let Some(mut watchlist) = watchlist else {
            return Err(ConnectorError::refused(
                PLATFORM,
                &cx.tenant.label.tenant,
                format!(
                    "The CBC Deployer cannot create a detection in a nonexistent Watchlist: {}. \
                     Create it on the console before retriggering deployment.",
                    plan.watchlist
                ),
                None,
            ));
        };
        let mut report: Option<Map<String, Value>> = None;
        let report_ids: Vec<String> = watchlist
            .get("report_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        for id in &report_ids {
            let found = Self::get(cx, &org, &format!("{reports_path}/{id}")).await?;
            if found.get("title").and_then(Value::as_str) == Some(plan.report.as_str())
                && let Some(object) = found.as_object()
            {
                report = Some(object.clone());
            }
        }
        let mut ioc = Map::new();
        ioc.insert("id".into(), Value::String(plan.uuid.clone()));
        ioc.insert("match_type".into(), Value::String("query".into()));
        ioc.insert(
            "values".into(),
            Value::Array(vec![Value::String(plan.query.replace('\n', " "))]),
        );
        let ioc = Value::Object(ioc);
        let own_report = plan.report == plan.name;
        let tags =
            |tags: &[String]| Value::Array(tags.iter().cloned().map(Value::String).collect());
        let Some(mut existing) = report else {
            if !plan.deployment {
                return Ok(ReportChange::Absent);
            }
            let mut body = Map::new();
            body.insert("title".into(), Value::String(plan.report.clone()));
            body.insert(
                "description".into(),
                Value::String(plan.description.clone()),
            );
            body.insert("severity".into(), Value::from(plan.severity));
            body.insert("timestamp".into(), Value::from(plan.now));
            let stripped: Vec<String> = plan.tags.iter().map(|tag| tag.trim().to_owned()).collect();
            body.insert("tags".into(), tags(&stripped));
            body.insert("iocs_v2".into(), Value::Array(vec![ioc]));
            let created = match Self::json(
                cx,
                &org,
                reqwest::Method::POST,
                &reports_path,
                Some(&Value::Object(body)),
            )
            .await?
            {
                Ok(value) => value.unwrap_or(Value::Null),
                Err(error) => return Err(Self::refused(cx, &error)),
            };
            let id = created
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let mut ids: Vec<Value> = report_ids.into_iter().map(Value::String).collect();
            ids.push(Value::String(id));
            watchlist.insert("report_ids".into(), Value::Array(ids));
            let id = watchlist
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if let Err(error) = Self::json(
                cx,
                &org,
                reqwest::Method::PUT,
                &format!("{watchlists_path}/{id}"),
                Some(&Value::Object(watchlist)),
            )
            .await?
            {
                return Err(Self::refused(cx, &error));
            }
            return Ok(ReportChange::Created);
        };
        let report_id = existing
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let report_path = format!("{reports_path}/{report_id}");
        let mut iocs: Vec<Value> = existing
            .get("iocs_v2")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let before = iocs.len();
        iocs.retain(|item| item.get("id").and_then(Value::as_str) != Some(plan.uuid.as_str()));
        let removed = iocs.len() < before;
        let current_severity = existing
            .get("severity")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let update = |existing: &mut Map<String, Value>,
                      iocs: Option<Vec<Value>>,
                      fields: &[(&str, Value)]| {
            for (key, value) in fields {
                if existing.contains_key(*key) {
                    existing.insert((*key).to_owned(), value.clone());
                }
            }
            existing.insert("timestamp".into(), Value::from(plan.now));
            if let Some(iocs) = iocs {
                existing.insert("iocs_v2".into(), Value::Array(iocs));
            }
        };
        if !plan.deployment {
            if own_report {
                return match Self::call(cx, &org, reqwest::Method::DELETE, &report_path, None)
                    .await?
                {
                    Ok(_) => Ok(ReportChange::Deleted),
                    Err(error) => Err(Self::refused(cx, &error)),
                };
            }
            if iocs.is_empty() {
                return match Self::call(cx, &org, reqwest::Method::DELETE, &report_path, None)
                    .await?
                {
                    Ok(_) => Ok(ReportChange::Deleted),
                    Err(error) => Err(Self::refused(cx, &error)),
                };
            }
            update(&mut existing, removed.then_some(iocs), &[]);
            if let Err(error) = Self::json(
                cx,
                &org,
                reqwest::Method::PUT,
                &report_path,
                Some(&Value::Object(existing)),
            )
            .await?
            {
                return Err(Self::refused(cx, &error));
            }
            return Ok(ReportChange::IocRemoved);
        }
        iocs.push(ioc);
        let mut all_tags = plan.tags.clone();
        let mut fields = vec![("description", Value::String(plan.description.clone()))];
        let raise = if own_report {
            plan.severity != current_severity
        } else {
            for tag in existing
                .get("tags")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if !all_tags.iter().any(|known| known == tag) {
                    all_tags.push(tag.to_owned());
                }
            }
            plan.severity > current_severity
        };
        fields.push(("tags", tags(&all_tags)));
        if raise {
            fields.push(("severity", Value::from(plan.severity)));
        }
        update(&mut existing, Some(iocs), &fields);
        if let Err(error) = Self::json(
            cx,
            &org,
            reqwest::Method::PUT,
            &report_path,
            Some(&Value::Object(existing)),
        )
        .await?
        {
            return Err(Self::refused(cx, &error));
        }
        Ok(ReportChange::Updated)
    }

    /// A process search over the request's window (`CarbonBlackQueryRunner.run`):
    /// validated, started, polled until it completes, read until one row
    /// more than the limit.
    pub async fn run(
        &self,
        cx: TenantContext<'_>,
        request: &QueryRequest,
    ) -> Result<QueryOutcome, ConnectorError> {
        let tenant = cx.tenant.label.tenant.clone();
        let org = Org::of(cx)?;
        let refused = |error: SdkError| match error {
            SdkError::Unauthorized(text) => ConnectorError::Authentication {
                platform: PLATFORM.into(),
                tenant: tenant.clone(),
                message: text,
                detail: None,
            },
            SdkError::Api(text) => ConnectorError::refused(
                PLATFORM,
                &tenant,
                format!("Carbon Black Cloud refused the query on {tenant}"),
                Some(text),
            ),
        };
        let processes = format!("/api/investigate/v2/orgs/{}/processes", org.key);
        let start = utc_z(request.window.start);
        let end = utc_z(request.window.end);
        let mut validation = Map::new();
        validation.insert("query".into(), Value::String(request.text.clone()));
        let validated = Self::json(
            cx,
            &org,
            reqwest::Method::POST,
            &format!("{processes}/search_validation"),
            Some(&Value::Object(validation)),
        )
        .await?
        .map_err(refused)?
        .unwrap_or(Value::Null);
        if !validated.get("valid").is_some_and(truthy) {
            let message = validated
                .get("invalid_message")
                .map(value_str)
                .unwrap_or_default();
            let sent = serde_json::json!({
                "time_range": {"start": start, "end": end},
                "query": request.text,
                "sort": null,
            });
            return Err(refused(SdkError::Api(format!(
                "Invalid query: {sent}: {message}"
            ))));
        }
        let mut window = Map::new();
        window.insert("end".into(), Value::String(end));
        window.insert("start".into(), Value::String(start));
        let mut job = Map::new();
        job.insert("query".into(), Value::String(request.text.clone()));
        job.insert("rows".into(), Value::from(JOB_ROWS));
        job.insert("sort".into(), Value::Null);
        job.insert("time_range".into(), Value::Object(window));
        let started = Self::json(
            cx,
            &org,
            reqwest::Method::POST,
            &format!("{processes}/search_jobs"),
            Some(&Value::Object(job)),
        )
        .await?
        .map_err(refused)?
        .unwrap_or(Value::Null);
        let submitted = Instant::now();
        let job_id = started.get("job_id").map(value_str).unwrap_or_default();
        let results = format!("{processes}/search_jobs/{job_id}/results");
        loop {
            let status = Self::json(
                cx,
                &org,
                reqwest::Method::GET,
                &format!("{results}?start=0&rows=0"),
                None,
            )
            .await?
            .map_err(refused)?
            .unwrap_or(Value::Null);
            let contacted = status.get("contacted").and_then(Value::as_i64).unwrap_or(0);
            let completed = status.get("completed").and_then(Value::as_i64).unwrap_or(0);
            let message = status.get("message").map(value_str).unwrap_or_default();
            if message.contains("No data available") {
                break;
            }
            if contacted != 0 && completed >= contacted {
                break;
            }
            if submitted.elapsed() > request.timeout {
                return Err(ConnectorError::QueryTimedOut {
                    platform: PLATFORM.into(),
                    tenant: tenant.clone(),
                    message: format!(
                        "the process search did not finish within {}s on {tenant}",
                        seconds_g(request.timeout)
                    ),
                    detail: Some("narrow the window or raise --timeout".into()),
                    timeout: request.timeout,
                });
            }
            tokio::select! {
                () = cx.cancel.cancelled() => return Err(ConnectorError::Cancelled),
                () = tokio::time::sleep(POLL_DELAY) => {}
            }
        }
        let wanted = request.limit.saturating_add(1);
        let mut found: Vec<Row> = Vec::new();
        let mut current: usize = 0;
        'pages: loop {
            let page = Self::call(
                cx,
                &org,
                reqwest::Method::GET,
                &format!("{results}?start={current}&rows={wanted}"),
                None,
            )
            .await?
            .map_err(refused)?;
            let body: Json = serde_json::from_slice(&page.body).unwrap_or(Json::Null);
            let total = match body.get("num_available") {
                Some(Json::Int(total)) => usize::try_from(*total).unwrap_or(0),
                _ => 0,
            };
            let items = match body.get("results") {
                Some(Json::Array(items)) => items.clone(),
                _ => Vec::new(),
            };
            if items.is_empty() && current < total {
                break;
            }
            for item in items {
                found.push(match item {
                    Json::Object(document) => flatten(&document),
                    _ => Row::new(),
                });
                current += 1;
                if found.len() >= wanted {
                    break 'pages;
                }
            }
            if current >= total {
                break;
            }
        }
        let shown: Vec<Row> = found.iter().take(request.limit).cloned().collect();
        Ok(QueryOutcome {
            columns: columns_of(&shown),
            truncated: found.len() > request.limit,
            rows: shown,
            partial: false,
            warnings: Vec::new(),
            vendor_query_id: None,
            sent: None,
            language: Some("lucene".into()),
        })
    }

    /// Carbon Black's `search_validation` (`CarbonBlackQueryRunner.check`):
    /// the query is parsed, no search runs.
    pub async fn check(
        &self,
        cx: TenantContext<'_>,
        request: &QueryRequest,
    ) -> Result<LiveCheck, ConnectorError> {
        let tenant = cx.tenant.label.tenant.clone();
        let org = Org::of(cx)?;
        let mut body = Map::new();
        body.insert("query".into(), Value::String(request.text.clone()));
        let answer = Self::json(
            cx,
            &org,
            reqwest::Method::POST,
            &format!(
                "/api/investigate/v2/orgs/{}/processes/search_validation",
                org.key
            ),
            Some(&Value::Object(body)),
        )
        .await?;
        let validated = match answer {
            Ok(value) => value.unwrap_or(Value::Null),
            Err(SdkError::Unauthorized(text)) => {
                return Err(ConnectorError::authentication(PLATFORM, &tenant, text));
            }
            Err(SdkError::Api(text)) => {
                return Err(ConnectorError::Answer {
                    platform: PLATFORM.into(),
                    tenant,
                    address: crate::error::origin(&url::Url::parse(&org.server).map_err(|_| {
                        ConnectorError::Setup {
                            platform: PLATFORM.into(),
                            tenant: cx.tenant.label.tenant.clone(),
                            message: "url is not a URL".into(),
                        }
                    })?),
                    reason: text,
                });
            }
        };
        if !validated.get("valid").is_some_and(truthy) {
            return Err(ConnectorError::refused(
                PLATFORM,
                &tenant,
                format!("Carbon Black Cloud refused the query on {tenant}"),
                Some("ensure each term has a value, and escape slashes, colons and spaces".into()),
            ));
        }
        Ok(LiveCheck::default())
    }
}

/// Python's truth of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `str(value)` of a JSON value from the SDK.
fn value_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// `{seconds:g}`.
fn seconds_g(duration: Duration) -> String {
    let seconds = duration.as_secs_f64();
    if seconds.fract() == 0.0 {
        format!("{seconds:.0}")
    } else {
        format!("{seconds}")
    }
}

impl Deployer for CarbonBlack {
    /// The rule's report: `body` is a JSON object with the
    /// [`ReportDeploy`] fields (`uuid`, `name`, `description`, `query`,
    /// `tags`, `severity`, `watchlist`, `report`); a disable or a delete
    /// retires the rule's IOC.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        Box::pin(async move {
            let setup = |message: &str| ConnectorError::Setup {
                platform: PLATFORM.into(),
                tenant: cx.tenant.label.tenant.clone(),
                message: message.to_owned(),
            };
            let body: Value = serde_json::from_slice(&request.body)
                .map_err(|_| setup("the compiled report is not JSON"))?;
            let text = |key: &str| {
                body.get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let name = text("name");
            let report = body
                .get("report")
                .and_then(Value::as_str)
                .filter(|report| !report.is_empty())
                .map_or_else(|| name.clone(), str::to_owned);
            let plan = ReportDeploy {
                uuid: text("uuid"),
                description: text("description"),
                query: text("query"),
                deployment: matches!(request.operation, Operation::Create | Operation::Update),
                tags: body
                    .get("tags")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(value_str)
                    .collect(),
                severity: body.get("severity").and_then(Value::as_i64).unwrap_or(3),
                watchlist: text("watchlist"),
                report,
                name,
                now: jiff::Timestamp::now().as_second(),
            };
            let change = self.deploy_report(cx, &plan).await?;
            Ok(DeployOutcome {
                remote_id: matches!(change, ReportChange::Created | ReportChange::Updated)
                    .then(|| request.rule_id.clone()),
                operation: request.operation,
            })
        })
    }
}

impl QueryRunner for CarbonBlack {
    /// A process search over the request's window.
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        Box::pin(CarbonBlack::run(self, cx, request))
    }
}

impl LiveValidator for CarbonBlack {
    /// `search_validation`: no search runs.
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        Box::pin(self.check(cx, request))
    }
}

impl Platform for CarbonBlack {
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

    fn answer(status: u16, body: &[u8]) -> Answer {
        Answer {
            status,
            content_type: None,
            body: body.to_vec(),
            elapsed: Duration::ZERO,
        }
    }

    #[test]
    fn error_statuses_read_as_the_sdk_words_them() {
        let uri = "https://cbc.invalid/x?y=1";
        assert_eq!(sdk_error("GET", uri, &answer(200, b"")), None);
        assert_eq!(
            sdk_error("GET", uri, &answer(502, b"")),
            Some(SdkError::Api(
                "Received error code 502 from API <https://cbc.invalid/x?y=1> (No further information provided)".into()
            ))
        );
        assert_eq!(
            sdk_error("GET", uri, &answer(404, b"gone")),
            Some(SdkError::Api(
                "Received 404 (Object Not Found) for https://cbc.invalid/x?y=1: gone".into()
            ))
        );
        assert_eq!(
            sdk_error("POST", uri, &answer(401, b"")),
            Some(SdkError::Unauthorized(
                "Unauthorized (Check API creds): attempted to POST https://cbc.invalid/x?y=1"
                    .into()
            ))
        );
        assert_eq!(
            sdk_error("POST", uri, &answer(400, br#"{"reason": "query_malformed_syntax"}"#)),
            Some(SdkError::Api(
                "Received query syntax error for https://cbc.invalid/x?y=1: {\"reason\": \"query_malformed_syntax\"}".into()
            ))
        );
        assert_eq!(seconds_g(Duration::from_millis(1500)), "1.5");
        assert_eq!(seconds_g(Duration::from_secs(120)), "120");
    }

    #[test]
    fn the_sdk_values_read_as_python_reads_them() {
        let value = |text: &str| serde_json::from_str::<Value>(text).unwrap_or(Value::Null);
        // Python's truth: `search_validation`'s `valid`.
        for falsy in ["null", "false", "0", "0.0", "\"\"", "[]", "{}"] {
            assert!(!truthy(&value(falsy)), "{falsy}");
        }
        for truthful in ["true", "1", "-0.5", "\"no\"", "[0]", "{\"a\": null}"] {
            assert!(truthy(&value(truthful)), "{truthful}");
        }
        // `str(value)`: a string as it is, anything else as its repr (the
        // job status's `message`, a tag that is not a string).
        assert_eq!(
            value_str(&value("\"No data available\"")),
            "No data available"
        );
        assert_eq!(value_str(&value("7")), "7");
        assert_eq!(value_str(&value("[true, null]")), "[True, None]");
        assert_eq!(value_str(&value("{\"a\": \"b\"}")), "{'a': 'b'}");
    }
}
