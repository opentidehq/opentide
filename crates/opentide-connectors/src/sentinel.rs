//! Microsoft Sentinel (UC-4.3, #833): the ARM `alertRules` calls of
//! `platforms/sentinel/client.py`, and its runner's Log Analytics queries,
//! one REST call each.
//!
//! Both sign in to Entra ID with the tenant's app registration
//! ([`crate::entra`]: `azure_tenant_id`, `azure_client_id`,
//! `azure_client_secret`), one token per tenant and resource (ARM's,
//! Log Analytics'), kept in the connector's [`TokenCache`] until it is due
//! for renewal. An API's `401` gets one new token and one resend.

use std::sync::Arc;
use std::time::Duration;

use opentide_compile::deploy::PATH_SEGMENT;
use opentide_compile::json::{Json, Object};
use percent_encoding::utf8_percent_encode;

use crate::answer::Answer;
use crate::connector::{
    BoxFuture, DeployEvent, DeployOutcome, DeployRequest, Deployer, LiveCheck, LiveValidator,
    Operation, Platform, Prober, QueryColumn, QueryOutcome, QueryRequest, QueryRunner,
    RULE_UNCHANGED, Row, TenantContext, kql_with_limit, probe_verdict,
};
use crate::entra::CredentialNames;
use crate::error::ConnectorError;
use crate::retry::RetryPolicy;
use crate::text::json_text;
use crate::token::TokenCache;
use crate::{HttpSettings, Secret};

/// The platform's identifier.
pub const PLATFORM: &str = "sentinel";

/// The tenant setup's names for the app registration.
pub const CREDENTIALS: CredentialNames = CredentialNames {
    tenant_id: "azure_tenant_id",
    client_id: "azure_client_id",
    client_secret: "azure_client_secret",
};
/// Azure Resource Manager.
pub const ARM_ENDPOINT: &str = "https://management.azure.com";
/// The scope of ARM's tokens.
pub const ARM_SCOPE: &str = "https://management.azure.com/.default";
/// Log Analytics' query API.
pub const LOGS_ENDPOINT: &str = "https://api.loganalytics.io/v1";
/// The scope of Log Analytics' tokens.
pub const LOGS_SCOPE: &str = "https://api.loganalytics.io/.default";
/// The `alertRules` API version (`ALERT_RULES_API_VERSION`): NRT rules exist
/// only in the preview versions.
pub const ALERT_RULES_API_VERSION: &str = "2025-10-01-preview";
/// The longest a Log Analytics query may run on the server (`server_timeout`).
pub const MAX_SERVER_TIMEOUT: Duration = Duration::from_secs(600);

/// The HTTP settings of a Sentinel tenant: *timeout* on each request, and
/// the connectors' retries.
pub fn http_settings(timeout: Duration) -> HttpSettings {
    HttpSettings {
        timeout,
        retry: RetryPolicy::standard(),
        ..HttpSettings::default()
    }
}

/// ARM's answer to an alert-rule call with an error status
/// (`SentinelApiError`).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{method} {url} failed with HTTP {status} {code}: {message}")]
pub struct ArmError {
    /// The method.
    pub method: String,
    /// The URL, without its query.
    pub url: String,
    /// The status.
    pub status: u16,
    /// ARM's `error.code`.
    pub code: String,
    /// ARM's `error.message`, else the answer's text.
    pub message: String,
}

/// The Sentinel connector.
#[derive(Debug, Default)]
pub struct Sentinel {
    tokens: Arc<TokenCache>,
}

impl Sentinel {
    /// A connector with no token yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// A connector whose tokens are kept in *tokens*.
    pub fn with_tokens(tokens: Arc<TokenCache>) -> Self {
        Self { tokens }
    }

    /// A bearer token for *scope*, signing in when none is kept.
    ///
    /// # Errors
    ///
    /// A credential that is not set, or a sign-in Entra ID refused.
    pub async fn token(
        &self,
        cx: TenantContext<'_>,
        scope: &'static str,
    ) -> Result<Secret, ConnectorError> {
        self.tokens
            .token(&cx.tenant.label, scope, || {
                crate::entra::sign_in(cx, CREDENTIALS, scope)
            })
            .await
    }

    /// Sends the request *build* makes with the token for *scope*; a `401`
    /// gets one new token and one resend.
    async fn send(
        &self,
        cx: TenantContext<'_>,
        scope: &'static str,
        build: impl Fn(&Secret) -> crate::transport::RequestBuilder,
    ) -> Result<Answer, ConnectorError> {
        self.tokens
            .send(
                cx,
                scope,
                || crate::entra::sign_in(cx, CREDENTIALS, scope),
                build,
                cx.cancel,
            )
            .await
    }

    /// The `alertRules` collection of the tenant's workspace, or one rule
    /// (`AlertRules._url`).
    fn rules_url(cx: TenantContext<'_>, rule_id: Option<&str>) -> Result<String, ConnectorError> {
        let subscription = cx.tenant.secret("azure_subscription_id")?.expose();
        let group = cx.tenant.secret("resource_group")?.expose();
        let workspace = cx.tenant.secret("workspace_name")?.expose();
        let mut url = format!(
            "{ARM_ENDPOINT}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.OperationalInsights/workspaces/{}/providers/Microsoft.SecurityInsights/alertRules",
            utf8_percent_encode(subscription, PATH_SEGMENT),
            utf8_percent_encode(group, PATH_SEGMENT),
            utf8_percent_encode(workspace, PATH_SEGMENT)
        );
        if let Some(rule_id) = rule_id {
            url.push('/');
            url.extend(utf8_percent_encode(rule_id, PATH_SEGMENT));
        }
        Ok(url)
    }

    /// One ARM call (`AlertRules._request`): the token, `api-version` unless
    /// the URL has one, and an error status as [`ArmError`].
    async fn arm(
        &self,
        cx: TenantContext<'_>,
        method: crate::transport::Method,
        url: &str,
        body: Option<&Json>,
    ) -> Result<Result<Answer, ArmError>, ConnectorError> {
        let sent = if url.contains("api-version=") {
            url.to_owned()
        } else {
            let joiner = if url.contains('?') { '&' } else { '?' };
            format!("{url}{joiner}api-version={ALERT_RULES_API_VERSION}")
        };
        let bytes =
            body.map(serde_json::to_vec)
                .transpose()
                .map_err(|error| ConnectorError::Setup {
                    platform: PLATFORM.into(),
                    tenant: cx.tenant.label.tenant.clone(),
                    message: format!("the request body cannot be written: {error}"),
                })?;
        let answer = self
            .send(cx, ARM_SCOPE, |token| {
                let builder = cx
                    .http
                    .request(method.clone(), &sent)
                    .header("Accept", "application/json")
                    .header("Authorization", format!("Bearer {}", token.expose()));
                match &bytes {
                    Some(bytes) => builder
                        .header("Content-Type", "application/json")
                        .body(bytes.clone()),
                    None => builder,
                }
            })
            .await?;
        // A 3xx is a failure: a redirect the client could not follow (no
        // `Location`) is not a rule written (#1142).
        if (200..300).contains(&answer.status) {
            return Ok(Ok(answer));
        }
        let (code, message) = arm_error(&answer);
        Ok(Err(ArmError {
            method: method.to_string(),
            url: url.split('?').next().unwrap_or_default().to_owned(),
            status: answer.status,
            code,
            message,
        }))
    }

    /// Creates or replaces the analytics rule *rule_id* with *rule*
    /// (`AlertRules.create_or_update`): ARM's answer, `{}` for none.
    pub async fn create_or_update(
        &self,
        cx: TenantContext<'_>,
        rule_id: &str,
        rule: &Json,
    ) -> Result<Result<Json, ArmError>, ConnectorError> {
        let url = Self::rules_url(cx, Some(rule_id))?;
        Ok(self
            .arm(cx, crate::transport::Method::PUT, &url, Some(rule))
            .await?
            .map(|answer| {
                if answer.body.is_empty() {
                    Json::Object(Object::new())
                } else {
                    answer.json().unwrap_or(Json::Null)
                }
            }))
    }

    /// The analytics rule *rule_id* as the workspace holds it, `None` for a
    /// 404 (`GET` of the resource the `PUT` writes, same `api-version`).
    pub async fn read(
        &self,
        cx: TenantContext<'_>,
        rule_id: &str,
    ) -> Result<Result<Option<Json>, ArmError>, ConnectorError> {
        let url = Self::rules_url(cx, Some(rule_id))?;
        match self
            .arm(cx, crate::transport::Method::GET, &url, None)
            .await?
        {
            Ok(answer) => match answer.json() {
                Some(held) => Ok(Ok(Some(held))),
                None => Err(ConnectorError::Answer {
                    platform: PLATFORM.into(),
                    tenant: cx.tenant.label.tenant.clone(),
                    address: ARM_ENDPOINT.into(),
                    reason: format!(
                        "reading the analytics rule: {}",
                        answer.not_json_page().unwrap_or_default()
                    ),
                }),
            },
            Err(error) if error.status == 404 => Ok(Ok(None)),
            Err(error) => Ok(Err(error)),
        }
    }

    /// Deletes the analytics rule *rule_id* (`AlertRules.delete`).
    pub async fn delete(
        &self,
        cx: TenantContext<'_>,
        rule_id: &str,
    ) -> Result<Result<(), ArmError>, ConnectorError> {
        let url = Self::rules_url(cx, Some(rule_id))?;
        Ok(self
            .arm(cx, crate::transport::Method::DELETE, &url, None)
            .await?
            .map(|_| ()))
    }

    /// Every analytics rule of the workspace, following `nextLink`
    /// (`AlertRules.list`) on ARM's origin only, each once, and for at most
    /// [`crate::paging::MAX_PAGES`] pages ([`crate::paging::NextLinks`]): a
    /// link elsewhere, a repeated one or one past the cap is
    /// [`ConnectorError::Answer`], and the token is never sent there.
    pub async fn list(
        &self,
        cx: TenantContext<'_>,
    ) -> Result<Result<Vec<Json>, ArmError>, ConnectorError> {
        // The first page as `arm` sends it, `api-version` included, so a link
        // back to it is known for the one already followed.
        let first = format!(
            "{}?api-version={ALERT_RULES_API_VERSION}",
            Self::rules_url(cx, None)?
        );
        let refused = |error: crate::paging::LinkError| ConnectorError::Answer {
            platform: PLATFORM.into(),
            tenant: cx.tenant.label.tenant.clone(),
            address: url::Url::parse(&first)
                .map(|url| crate::error::origin(&url))
                .unwrap_or_default(),
            reason: format!("listing the analytics rules: {error}"),
        };
        let mut links = crate::paging::NextLinks::new(&first).map_err(refused)?;
        let mut url = Some(first.clone());
        let mut rules = Vec::new();
        while let Some(current) = url.take() {
            let page = match self
                .arm(cx, crate::transport::Method::GET, &current, None)
                .await?
            {
                Ok(answer) => match answer.json() {
                    Some(page) => page,
                    None => {
                        return Err(ConnectorError::Answer {
                            platform: PLATFORM.into(),
                            tenant: cx.tenant.label.tenant.clone(),
                            address: ARM_ENDPOINT.into(),
                            reason: format!(
                                "listing the analytics rules: {}",
                                answer.not_json_page().unwrap_or_default()
                            ),
                        });
                    }
                },
                Err(error) => return Ok(Err(error)),
            };
            if let Some(Json::Array(items)) = page.get("value") {
                rules.extend(items.iter().cloned());
            }
            if let Some(link) = page
                .get("nextLink")
                .and_then(Json::as_str)
                .filter(|link| !link.is_empty())
            {
                url = Some(links.follow(link).map_err(refused)?);
            }
        }
        Ok(Ok(rules))
    }

    /// Runs *request* on the tenant's Log Analytics workspace
    /// (`SentinelQueryRunner.run`): the query with `| take limit+1`, over the
    /// window, waiting on the server at most the request's timeout (600 s).
    pub async fn run(
        &self,
        cx: TenantContext<'_>,
        request: &QueryRequest,
    ) -> Result<QueryOutcome, ConnectorError> {
        let tenant = cx.tenant.label.tenant.clone();
        for key in ["azure_tenant_id", "azure_client_id", "azure_client_secret"] {
            cx.tenant.secret(key)?;
        }
        let workspace = cx.tenant.secret("workspace_id")?.expose().to_owned();
        let sent = kql_with_limit(&request.text, request.limit);
        let mut body = Object::new();
        body.insert("query".into(), Json::Str(sent.clone()));
        body.insert(
            "timespan".into(),
            Json::Str(format!(
                "{}/{}",
                serialize_iso(request.window.start),
                serialize_iso(request.window.end)
            )),
        );
        body.insert("workspaces".into(), Json::Null);
        let bytes =
            serde_json::to_vec(&Json::Object(body)).map_err(|error| ConnectorError::Setup {
                platform: PLATFORM.into(),
                tenant: tenant.clone(),
                message: format!("the request body cannot be written: {error}"),
            })?;
        let wait = request.timeout.min(MAX_SERVER_TIMEOUT).as_secs();
        let url = format!(
            "{LOGS_ENDPOINT}/workspaces/{}/query",
            utf8_percent_encode(&workspace, PATH_SEGMENT)
        );
        let answer = self
            .send(cx, LOGS_SCOPE, |token| {
                cx.http
                    .request(crate::transport::Method::POST, &url)
                    .header("Accept", "application/json")
                    .header("Authorization", format!("Bearer {}", token.expose()))
                    .header("Content-Type", "application/json")
                    .header("Prefer", format!("wait={wait}"))
                    .body(bytes.clone())
            })
            .await?;
        if answer.status != 200 {
            return Err(ConnectorError::refused(
                PLATFORM,
                &tenant,
                format!("Log Analytics refused the query on {tenant}"),
                Some(inner_message(&answer)),
            ));
        }
        let Some(body) = answer.json() else {
            return Err(ConnectorError::refused(
                PLATFORM,
                &tenant,
                format!("Log Analytics refused the query on {tenant}"),
                answer.not_json_detail(),
            ));
        };
        let mut warnings = Vec::new();
        let partial = body
            .get("error")
            .is_some_and(|error| !matches!(error, Json::Null));
        if partial {
            warnings.push(format!(
                "partial result: {}",
                partial_message(&answer, &body)
            ));
        }
        let tables: &[Json] = match body.get("tables") {
            Some(Json::Array(tables)) => tables,
            _ => &[],
        };
        if tables.len() > 1 {
            warnings.push(format!(
                "the query returned {} tables; showing the first",
                tables.len()
            ));
        }
        let (columns, rows) = tables.first().map(table).unwrap_or_default();
        let truncated = rows.len() > request.limit;
        Ok(QueryOutcome {
            columns,
            rows: rows.into_iter().take(request.limit).collect(),
            truncated,
            partial,
            warnings,
            vendor_query_id: None,
            sent: (sent != request.text.trim()).then_some(sent),
            language: Some("kql".into()),
        })
    }

    /// `validate query --live`'s check: a search for one row over the
    /// request's window (`QueryRunner.check`).
    pub async fn check(
        &self,
        cx: TenantContext<'_>,
        request: &QueryRequest,
    ) -> Result<LiveCheck, ConnectorError> {
        let result = self.run(cx, &request.for_check()).await?;
        Ok(LiveCheck {
            result: Some(result),
            errors: Vec::new(),
            warnings: Vec::new(),
        })
    }
}

/// The `error.message` of a partial result, the request's credentials masked
/// (the rows around it are data and stay as they came).
/// The events of a deploy: what it did to the rule.
pub const RULE_CREATED: &str = "sentinel_rule_created";
/// See [`RULE_CREATED`].
pub const RULE_UPDATED: &str = "sentinel_rule_updated";

/// Server-populated members ARM adds to a rule; never compared.
const SERVER_FIELDS: [&str; 6] = [
    "etag",
    "id",
    "name",
    "type",
    "systemData",
    "lastModifiedUtc",
];

/// Whether the workspace's rule *held* has every member *sent* has, equal:
/// only what the request sends is compared (ARM's `etag`, `id`, `name`,
/// `type`, `systemData`, `lastModifiedUtc` and any default it fills in are
/// ignored).
fn holds(held: &Json, sent: &Json) -> bool {
    match (held.as_object(), sent.as_object()) {
        (Some(held), Some(sent)) => sent
            .iter()
            .filter(|(key, _)| !SERVER_FIELDS.contains(&key.as_str()))
            .all(|(key, value)| held.get(key).is_some_and(|have| holds_member(have, value))),
        _ => false,
    }
}

/// A number as text, `73.0` as `73`, so `73` and `73.0` are one value.
fn number(value: &Json) -> Option<String> {
    match value {
        Json::Int(_) | Json::UInt(_) | Json::Float(_) => {
            let text = value.to_compact();
            Some(text.strip_suffix(".0").map_or(text.clone(), str::to_owned))
        }
        _ => None,
    }
}

fn holds_member(held: &Json, sent: &Json) -> bool {
    if let (Some(held), Some(sent)) = (held.as_object(), sent.as_object()) {
        return sent
            .iter()
            .all(|(key, value)| held.get(key).is_some_and(|have| holds_member(have, value)));
    }
    if let (Some(held), Some(sent)) = (held.as_array(), sent.as_array()) {
        return held.len() == sent.len()
            && held
                .iter()
                .zip(sent)
                .all(|(have, want)| holds_member(have, want));
    }
    match (number(held), number(sent)) {
        (Some(held), Some(sent)) => held == sent,
        _ => held == sent,
    }
}

fn partial_message(answer: &Answer, body: &Json) -> String {
    body.get("error")
        .and_then(|error| error.get("message"))
        .map_or_else(
            || "null".to_owned(),
            |message| json_text(&answer.quoted(message)),
        )
}

/// ARM's `error.code` and `error.message` (`_arm_error`), else the text.
fn arm_error(answer: &Answer) -> (String, String) {
    let head = || answer.text().trim().chars().take(500).collect::<String>();
    match answer.quotable_json() {
        Some(body) => {
            let error = body.get("error").filter(|error| error.is_filled());
            let code = error
                .and_then(|error| error.get("code"))
                .filter(|code| code.is_filled())
                .map(json_text)
                .unwrap_or_default();
            let message = error
                .and_then(|error| error.get("message"))
                .filter(|message| message.is_filled())
                .map_or_else(head, json_text);
            (code, message)
        }
        None => (String::new(), head()),
    }
}

/// The KQL parser's message inside a Log Analytics error, else the error's
/// `code: message` (and its target), else its HTTP status.
fn inner_message(answer: &Answer) -> String {
    let body = answer.quotable_json().unwrap_or(Json::Null);
    let error = body
        .get("error")
        .filter(|error| error.as_object().is_some());
    if let Some(inner) = error
        .and_then(|error| error.get("innererror"))
        .filter(|inner| inner.as_object().is_some())
    {
        if let Some(message) = inner
            .get("innererror")
            .filter(|nested| nested.as_object().is_some())
            .and_then(|nested| nested.get("message"))
            .filter(|message| message.is_filled())
        {
            return json_text(message);
        }
        if let Some(message) = inner.get("message").filter(|message| message.is_filled()) {
            return json_text(message);
        }
    }
    match error {
        Some(error) => {
            let field = |name: &str| {
                error
                    .get(name)
                    .filter(|value| !value.is_null())
                    .map(json_text)
                    .filter(|text| !text.is_empty())
            };
            let mut text = match (field("code"), field("message")) {
                (Some(code), Some(message)) => format!("{code}: {message}"),
                (Some(text), None) | (None, Some(text)) => text,
                (None, None) => format!("HTTP {}", answer.status),
            };
            if let Some(target) = field("target") {
                text.push_str(&format!(" (target: {target})"));
            }
            text
        }
        None => {
            let reason = crate::transport::StatusCode::from_u16(answer.status)
                .ok()
                .and_then(|status| status.canonical_reason())
                .map(|reason| format!(" {reason}"))
                .unwrap_or_default();
            format!("Log Analytics answered HTTP {}{reason}", answer.status)
        }
    }
}

/// A Log Analytics table: its columns and its rows, each value as
/// azure-monitor-query reads it and opentide writes it (a `datetime` as
/// `format_utc_z`; `timespan` and `guid` as text).
fn table(table: &Json) -> (Vec<QueryColumn>, Vec<Row>) {
    let columns: Vec<(String, Option<String>)> = match table.get("columns") {
        Some(Json::Array(columns)) => columns
            .iter()
            .map(|column| {
                (
                    column.get("name").map(json_text).unwrap_or_default(),
                    column.get("type").map(json_text),
                )
            })
            .collect(),
        _ => Vec::new(),
    };
    let rows: Vec<Row> = match table.get("rows") {
        Some(Json::Array(rows)) => rows
            .iter()
            .filter_map(|row| match row {
                Json::Array(values) => Some(values),
                _ => None,
            })
            .map(|values| {
                let mut row = Row::new();
                for ((name, kind), value) in columns.iter().zip(values) {
                    row.insert(name.clone(), native(kind.as_deref(), value));
                }
                row
            })
            .collect(),
        _ => Vec::new(),
    };
    let columns = columns
        .into_iter()
        .map(|(name, kind)| QueryColumn { name, kind })
        .collect();
    (columns, rows)
}

/// A value of a column of type *kind* (`native_col_type`, then `json_safe`).
fn native(kind: Option<&str>, value: &Json) -> Json {
    match (kind, value) {
        (Some("datetime"), Json::Str(text)) => {
            datetime(text).map_or_else(|| value.clone(), Json::Str)
        }
        (Some("timespan" | "guid"), other) if !matches!(other, Json::Str(_)) => {
            Json::Str(json_text(other))
        }
        _ => value.clone(),
    }
}

/// An ISO 8601 date and time as `json_safe` writes the datetime
/// azure-monitor-query parses it into: UTC milliseconds with `Z` when it
/// has an offset, `isoformat()` when it has none; `None` when it is not one.
fn datetime(text: &str) -> Option<String> {
    let upper = text.to_uppercase();
    if let Ok(at) = upper.parse::<jiff::Timestamp>() {
        return Some(crate::connector::utc_z(at));
    }
    let civil = upper.parse::<jiff::civil::DateTime>().ok()?;
    let mut out = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        civil.year(),
        civil.month(),
        civil.day(),
        civil.hour(),
        civil.minute(),
        civil.second()
    );
    let micros = civil.subsec_nanosecond() / 1000;
    if micros != 0 {
        out.push_str(&format!(".{micros:06}"));
    }
    Some(out)
}

/// *at* as azure-core's `serialize_iso` writes it: UTC, at least three
/// fractional digits, trailing zeros beyond those dropped, `Z`.
pub fn serialize_iso(at: jiff::Timestamp) -> String {
    let civil = jiff::tz::Offset::UTC.to_datetime(at);
    let micros = format!("{:06}", civil.subsec_nanosecond() / 1000);
    let trimmed = micros.trim_end_matches('0');
    let fraction = format!("{trimmed:0<3}");
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{fraction}Z",
        civil.year(),
        civil.month(),
        civil.day(),
        civil.hour(),
        civil.minute(),
        civil.second()
    )
}

impl Sentinel {
    /// What a deploy does before its first rule: the workspace's address and
    /// the ARM token ([`Deployer::open`], and [`Prober::probe`]'s first step).
    async fn open_tenant(&self, cx: TenantContext<'_>) -> Result<(), ConnectorError> {
        Self::rules_url(cx, None)?;
        self.token(cx, ARM_SCOPE).await.map(|_| ())
    }
}

impl Prober for Sentinel {
    /// Opens the tenant as a deploy does (the Entra ID sign-in), then reads
    /// the first page of the workspace's analytics rules: `GET
    /// .../alertRules`, which writes nothing and needs the token.
    fn probe<'a>(
        &'a self,
        cx: TenantContext<'a>,
    ) -> BoxFuture<'a, Result<(), crate::connector::DeployError>> {
        crate::connector::probing(async move {
            self.open_tenant(cx).await?;
            let url = Self::rules_url(cx, None)?;
            match self
                .arm(cx, crate::transport::Method::GET, &url, None)
                .await?
            {
                Ok(_) => Ok(()),
                Err(error) => probe_verdict(
                    PLATFORM,
                    &cx.tenant.label.tenant,
                    "reading the analytics rules",
                    error.status,
                ),
            }
        })
    }
}

impl Deployer for Sentinel {
    /// The workspace's address and the ARM token, signed in once: the
    /// first rule's request reuses it.
    fn open<'a>(
        &'a self,
        cx: TenantContext<'a>,
    ) -> BoxFuture<'a, Result<(), crate::connector::DeployError>> {
        crate::connector::opening(self.open_tenant(cx))
    }

    /// The analytics rule `rule_id` (the rule's UUID): `PUT` with the
    /// compiled rule (a disabled rule is the rule with `enabled` false),
    /// `DELETE` for a delete.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, crate::connector::DeployError>> {
        Box::pin(async move {
            let refused = |error: ArmError| {
                ConnectorError::refused(PLATFORM, &cx.tenant.label.tenant, error.to_string(), None)
            };
            if request.operation == Operation::Delete {
                self.delete(cx, &request.rule_id).await?.map_err(refused)?;
                return Ok(DeployOutcome {
                    events: Vec::new(),
                    remote_id: None,
                    operation: request.operation,
                    warnings: Vec::new(),
                });
            }
            let body: Json =
                serde_json::from_slice(&request.body).map_err(|error| ConnectorError::Setup {
                    platform: PLATFORM.into(),
                    tenant: cx.tenant.label.tenant.clone(),
                    message: format!("the compiled rule is not JSON: {error}"),
                })?;
            // Read before writing (OT-3): a rule the workspace already holds
            // as the request has it is not written, and a failed read fails
            // the rule: it never falls through to the `PUT`.
            let event = match self.read(cx, &request.rule_id).await?.map_err(refused)? {
                None => RULE_CREATED,
                Some(held) if holds(&held, &body) => RULE_UNCHANGED,
                Some(_) => RULE_UPDATED,
            };
            if event != RULE_UNCHANGED {
                self.create_or_update(cx, &request.rule_id, &body)
                    .await?
                    .map_err(refused)?;
            }
            Ok(DeployOutcome {
                events: vec![
                    DeployEvent::new(event).with_field("rule_id", request.rule_id.clone()),
                ],
                remote_id: Some(request.rule_id.clone()),
                operation: request.operation,
                warnings: Vec::new(),
            })
        })
    }
}

impl QueryRunner for Sentinel {
    /// A Log Analytics query over the request's window.
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        Box::pin(Sentinel::run(self, cx, request))
    }
}

impl LiveValidator for Sentinel {
    /// A search for one row over the request's window.
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        Box::pin(self.check(cx, request))
    }
}

impl Platform for Sentinel {
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
    use crate::answer::{TEST_BEARER, answer_to_bearer};

    #[test]
    fn arm_and_log_analytics_errors_do_not_quote_the_bearer() {
        let arm = answer_to_bearer(&format!(
            r#"{{"error":{{"code":"c","message":"bad {TEST_BEARER}"}}}}"#
        ));
        assert_eq!(arm_error(&arm), ("c".to_owned(), "bad ***".to_owned()));
        let inner = answer_to_bearer(&format!(
            r#"{{"error":{{"innererror":{{"message":"parse {TEST_BEARER}"}}}}}}"#
        ));
        assert_eq!(inner_message(&inner), "parse ***");
        let plain = answer_to_bearer(&format!(
            r#"{{"error":{{"code":"c","message":"no {TEST_BEARER}"}}}}"#
        ));
        let message = inner_message(&plain);
        assert!(!message.contains(TEST_BEARER), "{message}");
    }

    #[test]
    fn a_partial_result_message_does_not_quote_the_bearer() {
        let mut answer = answer_to_bearer(&format!(
            r#"{{"error":{{"message":"cut {TEST_BEARER}"}},"tables":[{{"rows":[["{TEST_BEARER}"]]}}]}}"#
        ));
        answer.status = 200;
        let body = answer.json().unwrap();
        assert_eq!(partial_message(&answer, &body), "cut ***");
        assert!(body.to_compact().contains(TEST_BEARER), "rows are data");
    }

    #[test]
    fn instants_serialise_as_azure_core_writes_them() {
        let at = |text: &str| text.parse::<jiff::Timestamp>().unwrap();
        assert_eq!(
            serialize_iso(at("2026-10-26T08:00:00Z")),
            "2026-10-26T08:00:00.000Z"
        );
        assert_eq!(
            serialize_iso(at("2026-10-26T08:00:00.25Z")),
            "2026-10-26T08:00:00.250Z"
        );
        assert_eq!(
            serialize_iso(at("2026-10-26T08:00:00.123456Z")),
            "2026-10-26T08:00:00.123456Z"
        );
    }

    #[test]
    fn datetime_cells_read_as_json_safe_writes_them() {
        assert_eq!(
            datetime("2026-10-27T07:51:00.1234567Z").as_deref(),
            Some("2026-10-27T07:51:00.123Z")
        );
        assert_eq!(
            datetime("2026-10-27T09:51:00+02:00").as_deref(),
            Some("2026-10-27T07:51:00.000Z")
        );
        assert_eq!(
            datetime("2026-10-27T07:51:00").as_deref(),
            Some("2026-10-27T07:51:00")
        );
        assert_eq!(datetime("not a date"), None);
        assert_eq!(native(Some("guid"), &Json::Int(3)), Json::Str("3".into()));
    }
}
