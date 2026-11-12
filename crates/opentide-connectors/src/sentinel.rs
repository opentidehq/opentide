//! Microsoft Sentinel (UC-4.3, #833): what `platforms/sentinel/` sends,
//! request for request: the ARM `alertRules` calls of `client.py` (already
//! plain REST in Python), the sign-in azure-identity's
//! `ClientSecretCredential` makes through MSAL (the tenant's OpenID
//! configuration, then the OAuth2 client-credentials grant: the only
//! credential opentide uses), and `runner.py`'s Log Analytics queries, one
//! REST call each, in place of `azure-monitor-query`.
//!
//! A token is asked for once per tenant and scope (ARM's, Log Analytics')
//! and kept until it nearly expires, as MSAL's cache keeps it. MSAL and
//! azure-core stamp their requests with a fresh id (`client-request-id`,
//! `x-ms-client-request-id`): [`Sentinel::with_identity`] takes the source
//! of those ids and the operating system MSAL names (`x-client-os`), so a
//! test replays a recording made on another machine.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use opentide_compile::json::{Json, Object};

use crate::answer::Answer;
use crate::body::python_json;
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, LiveCheck, LiveValidator, Operation,
    Platform, QueryColumn, QueryOutcome, QueryRequest, QueryRunner, Row, TenantContext,
    kql_with_limit,
};
use crate::encode::{segment, urlencode};
use crate::error::ConnectorError;
use crate::python::python_str;
use crate::retry::RetryPolicy;
use crate::{HttpSettings, Secret, TenantLabel};

/// The platform's identifier.
pub const PLATFORM: &str = "sentinel";

/// Entra ID.
pub const LOGIN_ENDPOINT: &str = "https://login.microsoftonline.com";
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
/// The MSAL release the sign-in reads as (`x-client-ver`).
pub const MSAL_VERSION: &str = "1.39.0";
/// The longest a Log Analytics query may run on the server (`server_timeout`).
pub const MAX_SERVER_TIMEOUT: Duration = Duration::from_secs(600);

/// The HTTP settings of a Sentinel tenant: *timeout* on each request, and
/// the ARM session's `Retry(total=3, backoff_factor=0.8,
/// status_forcelist=[408, 429, 500, 502, 503, 504])` for `GET`, `PUT` and
/// `DELETE`.
pub fn http_settings(timeout: Duration) -> HttpSettings {
    HttpSettings {
        timeout,
        retry: RetryPolicy::urllib3(
            3,
            0.8,
            &[408, 429, 500, 502, 503, 504],
            &["GET", "PUT", "DELETE"],
        ),
        ..HttpSettings::default()
    }
}

/// The operating system as Python's `sys.platform` names it (`x-client-os`).
pub fn python_platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

/// A source of request ids.
pub type RequestIds = Arc<dyn Fn() -> String + Send + Sync>;

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

/// A cached token.
#[derive(Clone, Debug)]
struct Token {
    secret: Secret,
    until: Instant,
}

/// The Sentinel connector.
pub struct Sentinel {
    tokens: Mutex<BTreeMap<(TenantLabel, &'static str), Token>>,
    ids: RequestIds,
    client_os: String,
}

impl std::fmt::Debug for Sentinel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sentinel")
            .field("client_os", &self.client_os)
            .finish_non_exhaustive()
    }
}

impl Default for Sentinel {
    fn default() -> Self {
        Self::new()
    }
}

impl Sentinel {
    /// A connector with random request ids and this machine's `x-client-os`.
    pub fn new() -> Self {
        Self::with_identity(
            Arc::new(|| uuid::Uuid::new_v4().to_string()),
            python_platform(),
        )
    }

    /// A connector whose request ids come from *ids* and whose sign-in names
    /// *client_os*.
    pub fn with_identity(ids: RequestIds, client_os: &str) -> Self {
        Self {
            tokens: Mutex::new(BTreeMap::new()),
            ids,
            client_os: client_os.to_owned(),
        }
    }

    /// A bearer token for *scope*, signing in on first use
    /// (`ClientSecretCredential.get_token`).
    pub async fn token(
        &self,
        cx: TenantContext<'_>,
        scope: &'static str,
    ) -> Result<Secret, ConnectorError> {
        let key = (cx.tenant.label.clone(), scope);
        if let Some(token) = self
            .tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .filter(|token| token.until > Instant::now())
        {
            return Ok(token.secret.clone());
        }
        let token = self.sign_in(cx, scope).await?;
        self.tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, token.clone());
        Ok(token.secret)
    }

    /// MSAL's client-credentials flow: the authority's OpenID
    /// configuration, then the token.
    async fn sign_in(
        &self,
        cx: TenantContext<'_>,
        scope: &'static str,
    ) -> Result<Token, ConnectorError> {
        let tenant = cx.tenant.label.tenant.clone();
        let tenant_id = cx.tenant.secret("azure_tenant_id")?.expose().to_owned();
        let client_id = cx.tenant.secret("azure_client_id")?.expose().to_owned();
        let client_secret = cx.tenant.secret("azure_client_secret")?.expose().to_owned();
        let failed = |message: String| ConnectorError::Authentication {
            platform: PLATFORM.into(),
            tenant: tenant.clone(),
            message,
            detail: None,
        };
        let authority = format!("{LOGIN_ENDPOINT}/{tenant_id}");
        let discovery = cx
            .http
            .request(
                reqwest::Method::GET,
                &format!("{authority}/v2.0/.well-known/openid-configuration"),
            )
            .header("x-ms-client-request-id", (self.ids)());
        let answer = crate::answer::exchange(cx, discovery).await?;
        if answer.status != 200 {
            return Err(failed(format!(
                "Authentication failed: the authority {authority} answered its OpenID \
                 configuration with HTTP {}",
                answer.status
            )));
        }
        // MSAL draws a correlation id it does not send.
        let _ = (self.ids)();
        let form = urlencode([
            ("client_id", client_id.as_str()),
            ("grant_type", "client_credentials"),
            ("client_info", "1"),
            ("client_secret", client_secret.as_str()),
            ("scope", scope),
        ]);
        let request = cx
            .http
            .request(
                reqwest::Method::POST,
                &format!("{authority}/oauth2/v2.0/token"),
            )
            .header("Accept", "application/json")
            .header("client-request-id", (self.ids)())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("x-client-current-telemetry", "4|730,2|")
            .header("x-client-last-telemetry", "4|0|||")
            .header("x-client-os", self.client_os.as_str())
            .header("x-client-sku", "MSAL.Python")
            .header("x-client-ver", MSAL_VERSION)
            .header("x-ms-client-request-id", (self.ids)())
            .header("x-ms-lib-capability", "retry-after, h429")
            .body(form);
        let answer = crate::answer::exchange(cx, request).await?;
        let body = answer.json().unwrap_or(Json::Null);
        let token = body
            .get("access_token")
            .and_then(Json::as_str)
            .filter(|token| !token.is_empty());
        match token {
            Some(token) if answer.status == 200 => {
                let seconds = match body.get("expires_in") {
                    Some(Json::Int(seconds)) => u64::try_from(*seconds).unwrap_or(0),
                    Some(Json::Str(text)) => text.parse().unwrap_or(0),
                    _ => 0,
                };
                // Asked for again five minutes before it expires.
                let lifetime = Duration::from_secs(seconds.saturating_sub(300));
                Ok(Token {
                    secret: Secret::new(token),
                    until: Instant::now() + lifetime,
                })
            }
            _ => {
                let reason = body
                    .get("error_description")
                    .filter(|value| value.truthy())
                    .or_else(|| body.get("error"))
                    .map_or_else(|| format!("HTTP {}", answer.status), python_str);
                Err(failed(format!("Authentication failed: {reason}")))
            }
        }
    }

    /// The `alertRules` collection of the tenant's workspace, or one rule
    /// (`AlertRules._url`).
    fn rules_url(cx: TenantContext<'_>, rule_id: Option<&str>) -> Result<String, ConnectorError> {
        let subscription = cx.tenant.secret("azure_subscription_id")?.expose();
        let group = cx.tenant.secret("resource_group")?.expose();
        let workspace = cx.tenant.secret("workspace_name")?.expose();
        let mut url = format!(
            "{ARM_ENDPOINT}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.OperationalInsights/workspaces/{}/providers/Microsoft.SecurityInsights/alertRules",
            segment(subscription),
            segment(group),
            segment(workspace)
        );
        if let Some(rule_id) = rule_id {
            url.push('/');
            url.push_str(&segment(rule_id));
        }
        Ok(url)
    }

    /// One ARM call (`AlertRules._request`): the token, `api-version` unless
    /// the URL has one, and an error status as [`ArmError`].
    async fn arm(
        &self,
        cx: TenantContext<'_>,
        method: reqwest::Method,
        url: &str,
        body: Option<&Json>,
    ) -> Result<Result<Answer, ArmError>, ConnectorError> {
        let token = self.token(cx, ARM_SCOPE).await?;
        let sent = if url.contains("api-version=") {
            url.to_owned()
        } else {
            let joiner = if url.contains('?') { '&' } else { '?' };
            format!("{url}{joiner}api-version={ALERT_RULES_API_VERSION}")
        };
        let mut builder = cx
            .http
            .request(method.clone(), &sent)
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {}", token.expose()));
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
        if answer.status < 400 {
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
            .arm(cx, reqwest::Method::PUT, &url, Some(rule))
            .await?
            .map(|answer| {
                if answer.body.is_empty() {
                    Json::Object(Object::new())
                } else {
                    answer.json().unwrap_or(Json::Null)
                }
            }))
    }

    /// Deletes the analytics rule *rule_id* (`AlertRules.delete`).
    pub async fn delete(
        &self,
        cx: TenantContext<'_>,
        rule_id: &str,
    ) -> Result<Result<(), ArmError>, ConnectorError> {
        let url = Self::rules_url(cx, Some(rule_id))?;
        Ok(self
            .arm(cx, reqwest::Method::DELETE, &url, None)
            .await?
            .map(|_| ()))
    }

    /// Every analytics rule of the workspace, following `nextLink`
    /// (`AlertRules.list`).
    pub async fn list(
        &self,
        cx: TenantContext<'_>,
    ) -> Result<Result<Vec<Json>, ArmError>, ConnectorError> {
        let mut url = Some(Self::rules_url(cx, None)?);
        let mut rules = Vec::new();
        while let Some(current) = url.take() {
            let page = match self.arm(cx, reqwest::Method::GET, &current, None).await? {
                Ok(answer) => answer.json().unwrap_or(Json::Null),
                Err(error) => return Ok(Err(error)),
            };
            if let Some(Json::Array(items)) = page.get("value") {
                rules.extend(items.iter().cloned());
            }
            url = page
                .get("nextLink")
                .and_then(Json::as_str)
                .filter(|link| !link.is_empty())
                .map(str::to_owned);
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
        // azure-core stamps the request before it asks for the token.
        let request_id = (self.ids)();
        let token = self.token(cx, LOGS_SCOPE).await?;
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
        let bytes = python_json(&Json::Object(body)).map_err(|error| ConnectorError::Setup {
            platform: PLATFORM.into(),
            tenant: tenant.clone(),
            message: format!("the request body cannot be written: {error}"),
        })?;
        let wait = request.timeout.min(MAX_SERVER_TIMEOUT).as_secs();
        let builder = cx
            .http
            .request(
                reqwest::Method::POST,
                &format!("{LOGS_ENDPOINT}/workspaces/{}/query", segment(&workspace)),
            )
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {}", token.expose()))
            .header("Content-Type", "application/json")
            .header("Prefer", format!("wait={wait}"))
            .header("x-ms-client-request-id", request_id)
            .body(bytes);
        let answer = crate::answer::exchange(cx, builder).await?;
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
            let message = body
                .get("error")
                .and_then(|error| error.get("message"))
                .map_or_else(|| "None".to_owned(), python_str);
            warnings.push(format!("partial result: {message}"));
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

/// ARM's `error.code` and `error.message` (`_arm_error`), else the text.
fn arm_error(answer: &Answer) -> (String, String) {
    let head = || answer.text().trim().chars().take(500).collect::<String>();
    match answer.json() {
        Some(body) => {
            let error = body.get("error").filter(|error| error.truthy());
            let code = error
                .and_then(|error| error.get("code"))
                .filter(|code| code.truthy())
                .map(python_str)
                .unwrap_or_default();
            let message = error
                .and_then(|error| error.get("message"))
                .filter(|message| message.truthy())
                .map_or_else(head, python_str);
            (code, message)
        }
        None => (String::new(), head()),
    }
}

/// The KQL parser's message inside a Log Analytics error (`_inner_message`),
/// else azure-core's text of the error.
fn inner_message(answer: &Answer) -> String {
    let body = answer.json().unwrap_or(Json::Null);
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
            .filter(|message| message.truthy())
        {
            return python_str(message);
        }
        if let Some(message) = inner.get("message").filter(|message| message.truthy()) {
            return python_str(message);
        }
    }
    match error {
        Some(error) => {
            let code = error
                .get("code")
                .map_or_else(|| "None".to_owned(), python_str);
            let message = error
                .get("message")
                .map_or_else(|| "None".to_owned(), python_str);
            let mut text = format!("({code}) {message}\nCode: {code}\nMessage: {message}");
            if let Some(target) = error.get("target").filter(|target| target.truthy()) {
                text.push_str(&format!("\nTarget: {}", python_str(target)));
            }
            text
        }
        None => {
            let reason = reqwest::StatusCode::from_u16(answer.status)
                .ok()
                .and_then(|status| status.canonical_reason())
                .unwrap_or("");
            format!("Operation returned an invalid status '{reason}'")
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
                    column.get("name").map(python_str).unwrap_or_default(),
                    column.get("type").map(python_str),
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
            Json::Str(python_str(other))
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

impl Deployer for Sentinel {
    /// The analytics rule `rule_id` (the rule's UUID): `PUT` with the
    /// compiled rule (a disabled rule is the rule with `enabled` false),
    /// `DELETE` for a delete.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        Box::pin(async move {
            let refused = |error: ArmError| {
                ConnectorError::refused(PLATFORM, &cx.tenant.label.tenant, error.to_string(), None)
            };
            if request.operation == Operation::Delete {
                self.delete(cx, &request.rule_id).await?.map_err(refused)?;
                return Ok(DeployOutcome {
                    remote_id: None,
                    operation: request.operation,
                });
            }
            let body: Json =
                serde_json::from_slice(&request.body).map_err(|error| ConnectorError::Setup {
                    platform: PLATFORM.into(),
                    tenant: cx.tenant.label.tenant.clone(),
                    message: format!("the compiled rule is not JSON: {error}"),
                })?;
            self.create_or_update(cx, &request.rule_id, &body)
                .await?
                .map_err(refused)?;
            Ok(DeployOutcome {
                remote_id: Some(request.rule_id.clone()),
                operation: request.operation,
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
