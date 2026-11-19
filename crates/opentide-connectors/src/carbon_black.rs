//! Carbon Black Cloud (UC-4.3, #833): what `platforms/carbon_black/` sends
//! through cbc_sdk, request for request: the watchlist reports its
//! `deployer.py` writes (`_deploy_to_org`), `runner.py`'s process searches
//! (`opentide query`) and its `search_validation` check (`validate query
//! --live`).
//!
//! Every call carries `X-Auth-Token: <token>`; a body is compact JSON with
//! `Content-Type: application/json`. A search is validated, started as a job, polled every
//! half second until every searcher completed (or the timeout passed), then
//! read in pages. An error status is the SDK's exception, worded as it is.

use std::time::{Duration, Instant};

use opentide_compile::json::Json;
use serde_json::{Map, Value};

use crate::answer::Answer;
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, DeployWarning, Deployer, LiveCheck, LiveValidator,
    Operation, Platform, QueryOutcome, QueryRequest, QueryRunner, Row, TenantContext, columns_of,
    flatten, utc_z,
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
/// request, and the connectors' retries.
pub fn http_settings(timeout: Duration) -> HttpSettings {
    HttpSettings {
        timeout,
        retry: RetryPolicy::standard(),
        ..HttpSettings::default()
    }
}

/// An error status Carbon Black Cloud answered, by what it means for the
/// run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkError {
    /// HTTP 401: the API key was refused.
    Unauthorized(String),
    /// Any other error status.
    Api(String),
}

impl SdkError {
    /// What happened.
    pub fn text(&self) -> &str {
        match self {
            Self::Unauthorized(text) | Self::Api(text) => text,
        }
    }
}

/// The error *answer* to `method uri` is, or `None` for a 2xx: a 3xx is an
/// error too, a redirect the client could not follow (#1142):
/// `Carbon Black Cloud answered HTTP <status> <reason> to <method> <uri>`,
/// then the body's text when there is one.
fn sdk_error(method: &str, uri: &str, answer: &Answer) -> Option<SdkError> {
    let status = answer.status;
    if (200..300).contains(&status) {
        return None;
    }
    let reason = crate::transport::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .map(|reason| format!(" {reason}"))
        .unwrap_or_default();
    let mut message =
        format!("Carbon Black Cloud answered HTTP {status}{reason} to {method} {uri}");
    if status == 401 {
        message.push_str(" (check the API ID and key)");
    }
    let text = answer.text();
    let text = text.trim();
    if !text.is_empty() {
        message.push_str(&format!(": {text}"));
    }
    Some(if status == 401 {
        SdkError::Unauthorized(message)
    } else {
        SdkError::Api(message)
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
        method: crate::transport::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Result<Answer, SdkError>, ConnectorError> {
        let uri = format!("{}{path}", org.server);
        let mut builder = cx
            .http
            .request(method.clone(), &uri)
            .header("X-Auth-Token", org.token.expose());
        if let Some(body) = body {
            let bytes = serde_json::to_vec(body).map_err(|error| ConnectorError::Setup {
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
        method: crate::transport::Method,
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
            Err(error) => Ok(Err(SdkError::Api(format!(
                "Carbon Black Cloud answered HTTP {} with a body that is not JSON ({error}): {}",
                answer.status,
                answer.text().trim()
            )))),
        }
    }

    /// `get_object` in a deploy: the JSON, or the SDK's exception raised.
    async fn get(cx: TenantContext<'_>, org: &Org, path: &str) -> Result<Value, ConnectorError> {
        match Self::json(cx, org, crate::transport::Method::GET, path, None).await? {
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
    #[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
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
                crate::transport::Method::POST,
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
                crate::transport::Method::PUT,
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
                return match Self::call(
                    cx,
                    &org,
                    crate::transport::Method::DELETE,
                    &report_path,
                    None,
                )
                .await?
                {
                    Ok(_) => Ok(ReportChange::Deleted),
                    Err(error) => Err(Self::refused(cx, &error)),
                };
            }
            if iocs.is_empty() {
                return match Self::call(
                    cx,
                    &org,
                    crate::transport::Method::DELETE,
                    &report_path,
                    None,
                )
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
                crate::transport::Method::PUT,
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
            crate::transport::Method::PUT,
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
    #[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
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
            crate::transport::Method::POST,
            &format!("{processes}/search_validation"),
            Some(&Value::Object(validation)),
        )
        .await?
        .map_err(refused)?
        .unwrap_or(Value::Null);
        if validated.get("valid").and_then(Value::as_bool) != Some(true) {
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
            crate::transport::Method::POST,
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
                crate::transport::Method::GET,
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
                        request.timeout.as_secs_f64()
                    ),
                    detail: Some("narrow the window or raise --timeout".into()),
                    timeout: request.timeout,
                });
            }
            tokio::select! {
                biased;
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
                crate::transport::Method::GET,
                &format!("{results}?start={current}&rows={wanted}"),
                None,
            )
            .await?
            .map_err(refused)?;
            // A page that is not JSON is an error, never an empty page (#1142).
            let Some(body) = page.json() else {
                return Err(ConnectorError::Answer {
                    platform: PLATFORM.into(),
                    tenant: cx.tenant.label.tenant.clone(),
                    address: url::Url::parse(&org.server)
                        .map(|url| crate::error::origin(&url))
                        .unwrap_or_else(|_| org.server.clone()),
                    reason: format!(
                        "reading the search's results: {}",
                        page.not_json_page().unwrap_or_default()
                    ),
                });
            };
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
            crate::transport::Method::POST,
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
        if validated.get("valid").and_then(Value::as_bool) != Some(true) {
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

/// `str(value)` of a JSON value from the SDK.
fn value_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

impl Deployer for CarbonBlack {
    /// The organisation's `url`, `org_key` and `token`: nothing is sent.
    fn open<'a>(
        &'a self,
        cx: TenantContext<'a>,
    ) -> BoxFuture<'a, Result<(), crate::connector::DeployError>> {
        crate::connector::opening(async move {
            Org::of(cx).map(|_| ())
        })
    }

    /// The rule's report: `body` is a JSON object with the
    /// [`ReportDeploy`] fields (`uuid`, `name`, `description`, `query`,
    /// `tags`, `severity`, `watchlist`, `report`); a disable or a delete
    /// retires the rule's IOC. A report the retirement deletes is said, not
    /// raised: `report_deleted_with_rule` when the report was the rule's own,
    /// `report_auto_deleted` when the rule's IOC was its last, each naming
    /// the report. The report is stamped with the request's time.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, crate::connector::DeployError>> {
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
                now: request.time().as_second(),
            };
            let change = self.deploy_report(cx, &plan).await?;
            let deleted = match change {
                ReportChange::Deleted if plan.report == plan.name => {
                    Some("report_deleted_with_rule")
                }
                ReportChange::Deleted => Some("report_auto_deleted"),
                _ => None,
            };
            Ok(DeployOutcome {
                events: Vec::new(),
                remote_id: matches!(change, ReportChange::Created | ReportChange::Updated)
                    .then(|| request.rule_id.clone()),
                operation: request.operation,
                warnings: deleted
                    .map(|code| DeployWarning::new(code, plan.report.clone()).unraised())
                    .into_iter()
                    .collect(),
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
            credentials: crate::answer::Credentials::default(),
        }
    }

    #[test]
    fn error_statuses_name_the_status_the_call_and_the_answer() {
        let uri = "https://cbc.invalid/x?y=1";
        assert_eq!(sdk_error("GET", uri, &answer(200, b"")), None);
        // #1142: a redirect the client could not follow is no success.
        assert_eq!(
            sdk_error("PUT", uri, &answer(307, b"")),
            Some(SdkError::Api(
                "Carbon Black Cloud answered HTTP 307 Temporary Redirect to PUT \
                 https://cbc.invalid/x?y=1"
                    .into()
            ))
        );
        assert_eq!(
            sdk_error("GET", uri, &answer(502, b"")),
            Some(SdkError::Api(
                "Carbon Black Cloud answered HTTP 502 Bad Gateway to GET https://cbc.invalid/x?y=1"
                    .into()
            ))
        );
        assert_eq!(
            sdk_error("GET", uri, &answer(404, b"gone\n")),
            Some(SdkError::Api(
                "Carbon Black Cloud answered HTTP 404 Not Found to GET https://cbc.invalid/x?y=1: \
                 gone"
                    .into()
            ))
        );
        assert_eq!(
            sdk_error("POST", uri, &answer(401, b"")),
            Some(SdkError::Unauthorized(
                "Carbon Black Cloud answered HTTP 401 Unauthorized to POST \
                 https://cbc.invalid/x?y=1 (check the API ID and key)"
                    .into()
            ))
        );
        assert_eq!(
            sdk_error(
                "POST",
                uri,
                &answer(400, br#"{"reason": "query_malformed_syntax"}"#)
            ),
            Some(SdkError::Api(
                "Carbon Black Cloud answered HTTP 400 Bad Request to POST \
                 https://cbc.invalid/x?y=1: {\"reason\": \"query_malformed_syntax\"}"
                    .into()
            ))
        );
        assert_eq!(
            format!("{}s", Duration::from_millis(1500).as_secs_f64()),
            "1.5s"
        );
        assert_eq!(
            format!("{}s", Duration::from_secs(120).as_secs_f64()),
            "120s"
        );
    }

    #[test]
    fn the_sdk_values_read_as_python_reads_them() {
        let value = |text: &str| serde_json::from_str::<Value>(text).unwrap_or(Value::Null);
        // A string as it is, anything else as its JSON (the job status's
        // `message`, a tag that is not a string).
        assert_eq!(
            value_str(&value("\"No data available\"")),
            "No data available"
        );
        assert_eq!(value_str(&value("7")), "7");
        assert_eq!(value_str(&value("[true, null]")), "[true,null]");
        assert_eq!(value_str(&value("{\"a\": \"b\"}")), r#"{"a":"b"}"#);
    }
}
