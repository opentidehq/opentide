//! Microsoft Defender through the Microsoft Graph beta security API
//! (microsoft-defender-1.0, RFC 0021): custom detection rules addressed by
//! `opentide-<metadata.uuid>` (#1886), advanced hunting (`runHuntingQuery`) for
//! `opentide query` and `validate query --live`, and the columns a custom
//! detection needs.
//!
//! The client signs in to Entra ID with the tenant's app registration
//! ([`crate::entra`]: `tenant_id`, `client_id`, `client_secret`, scope
//! Graph's), keeps the token until it is due for renewal (a `401` gets one
//! new token and one resend), and sends every call to Graph's beta security
//! API with the bearer token and `Content-Type: application/json`.
//!
//! Deploy keeps no deployment state ([`MicrosoftDefender::deploy`]): the
//! rule id is `opentide-` and the rule's lowercase canonical uuid
//! ([`opentide_compile::microsoft_defender::rule_id_of`]), since Graph
//! refuses an id that begins with a digit. An active status sends
//! `PATCH {base}/{id}`, and on a `404` `POST {base}` with `id`; a `409` on
//! that `POST` (a concurrent create) is followed by one more `PATCH`, and
//! when that one finds no rule either, the `409` was another rule holding
//! the name ([`RULE_CONFLICT`]). A DISABLEMENT is a `PATCH` with
//! `status: disabled`, and a `404` there creates nothing ([`RULE_ABSENT`]).
//! A DELETION is a `DELETE`, whose `404` is the rule already gone.

use std::sync::Arc;

use opentide_compile::json::{Json, Object};

use crate::answer::Answer;
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, DeployWarning, Deployer, LiveCheck, LiveValidator,
    Operation, Platform, Prober, QueryColumn, QueryOutcome, QueryRequest, QueryRunner, Row,
    TenantContext, kql_with_limit, probe_verdict, utc_z,
};
use crate::entra::CredentialNames;
use crate::error::ConnectorError;
use crate::retry::RetryPolicy;
use crate::token::TokenCache;
use crate::{HttpSettings, Secret};

/// The platform's identifier.
pub const PLATFORM: &str = opentide_schema::objects::platform::microsoft_defender::PLATFORM;

/// The tenant setup's names for the app registration.
pub const CREDENTIALS: CredentialNames = CredentialNames {
    tenant_id: "tenant_id",
    client_id: "client_id",
    client_secret: "client_secret",
};
/// Graph's security API.
pub const GRAPH_API_ENDPOINT: &str = "https://graph.microsoft.com/beta/security";
/// The custom detection rules collection.
pub const DETECTION_RULES_ENDPOINT: &str = opentide_compile::microsoft_defender::ENDPOINT;
/// Advanced hunting.
pub const HUNTING_QUERY_ENDPOINT: &str =
    "https://graph.microsoft.com/beta/security/runHuntingQuery";
/// The scope the client credentials are granted for.
pub const SCOPE: &str = "https://graph.microsoft.com/.default";

/// Advanced hunting keeps 30 days of data; Graph refuses a longer timespan.
pub const MAX_LOOKBACK_DAYS: i64 = 30;

/// The HTTP settings of a Microsoft Defender tenant: 120 s and the connectors'
/// retries.
pub fn http_settings() -> HttpSettings {
    HttpSettings {
        retry: RetryPolicy::standard(),
        ..HttpSettings::default()
    }
}

/// Why a Graph call failed.
#[derive(Debug, thiserror::Error)]
pub enum DefenderError {
    /// Entra ID did not issue a token (`TenantConnectionError`).
    #[error("Cannot authenticate with the tenant configuration")]
    Authentication {
        /// What Entra ID answered.
        detail: String,
    },
    /// Graph refused a rule call (`DetectionRuleCreationFailed`,
    /// `DetectionRuleUpdateFailed`, `DetectionRuleDeletionFailed`).
    #[error("{message}")]
    Refused {
        /// The call and the tenant.
        message: String,
        /// Graph's answer (`str(_error_body(response))`).
        context: Option<String>,
    },
    /// The tenant could not be reached, or the run was cancelled.
    #[error(transparent)]
    Connector(#[from] ConnectorError),
}

impl DefenderError {
    /// The error as the framework's: a refused sign-in is the tenant's
    /// [`ConnectorError::Authentication`], a refused rule call its
    /// [`ConnectorError::Refused`].
    pub fn into_connector(self, tenant: &str) -> ConnectorError {
        match self {
            Self::Connector(error) => error,
            Self::Authentication { detail } => ConnectorError::Authentication {
                platform: PLATFORM.into(),
                tenant: tenant.to_owned(),
                message: "Cannot authenticate with the tenant configuration".into(),
                detail: Some(detail),
            },
            Self::Refused { message, context } => {
                ConnectorError::refused(PLATFORM, tenant, message, context)
            }
        }
    }
}

/// The Microsoft Defender connector. A tenant's token serves every call
/// until it is due for renewal.
#[derive(Debug, Default)]
pub struct MicrosoftDefender {
    tokens: Arc<TokenCache>,
}

/// A sign-in Entra ID refused as [`DefenderError::Authentication`]; any
/// other error as it is.
fn authentication(error: ConnectorError) -> DefenderError {
    match error {
        ConnectorError::Authentication {
            message, detail, ..
        } => DefenderError::Authentication {
            detail: match detail {
                Some(said) => format!("{message}: {said}"),
                None => message,
            },
        },
        other => DefenderError::Connector(other),
    }
}

impl MicrosoftDefender {
    /// A connector with no tenant signed in yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// A connector whose tokens are kept in *tokens*.
    pub fn with_tokens(tokens: Arc<TokenCache>) -> Self {
        Self { tokens }
    }

    /// The tenant's bearer token, signing in when none is kept.
    pub async fn token(&self, cx: TenantContext<'_>) -> Result<Secret, DefenderError> {
        self.tokens
            .token(&cx.tenant.label, SCOPE, || {
                crate::entra::sign_in(cx, CREDENTIALS, SCOPE)
            })
            .await
            .map_err(authentication)
    }

    /// A call to Graph with the session's headers.
    async fn graph(
        &self,
        cx: TenantContext<'_>,
        method: crate::transport::Method,
        url: &str,
        body: Option<&Json>,
    ) -> Result<Answer, DefenderError> {
        let bytes = body.map(|body| json_body(cx, body)).transpose()?;
        self.tokens
            .send(
                cx,
                SCOPE,
                || crate::entra::sign_in(cx, CREDENTIALS, SCOPE),
                |token| {
                    let builder = cx
                        .http
                        .request(method.clone(), url)
                        .header("Authorization", format!("Bearer {}", token.expose()))
                        .header("Content-Type", "application/json");
                    match &bytes {
                        Some(bytes) => builder.body(bytes.clone()),
                        None => builder,
                    }
                },
                cx.cancel,
            )
            .await
            .map_err(authentication)
    }

    /// Every custom detection rule of the tenant, across Graph's pages
    /// (`MicrosoftDefenderImporter.list_rules`, UC-4.4b): `@odata.nextLink`
    /// is followed on Graph's origin only, each once, and for at most
    /// [`crate::paging::MAX_PAGES`] pages ([`crate::paging::NextLinks`]: a
    /// link elsewhere never receives the token), and an error answer is an
    /// error, never an empty listing.
    pub async fn list_rules(&self, cx: TenantContext<'_>) -> Result<Vec<Json>, DefenderError> {
        let refused = |error: crate::paging::LinkError| {
            DefenderError::Connector(ConnectorError::Answer {
                platform: PLATFORM.into(),
                tenant: cx.tenant.label.tenant.clone(),
                address: "https://graph.microsoft.com".into(),
                reason: format!("listing the detection rules: {error}"),
            })
        };
        let mut links = crate::paging::NextLinks::new(DETECTION_RULES_ENDPOINT).map_err(refused)?;
        let mut rules = Vec::new();
        let mut next = Some(DETECTION_RULES_ENDPOINT.to_owned());
        while let Some(url) = next.take() {
            let answer = self
                .graph(cx, crate::transport::Method::GET, &url, None)
                .await?;
            if !(200..300).contains(&answer.status) {
                let reason = crate::transport::StatusCode::from_u16(answer.status)
                    .ok()
                    .and_then(|status| status.canonical_reason())
                    .unwrap_or_default();
                return Err(DefenderError::Refused {
                    message: format!(
                        "Listing Microsoft Defender detection rules on tenant {} failed with \
                         HTTP {} {reason}",
                        cx.tenant.label.tenant, answer.status
                    ),
                    context: None,
                });
            }
            let Some(page) = answer.json() else {
                return Err(DefenderError::Connector(ConnectorError::Answer {
                    platform: PLATFORM.into(),
                    tenant: cx.tenant.label.tenant.clone(),
                    address: "https://graph.microsoft.com".into(),
                    reason: format!(
                        "listing the detection rules: {}",
                        answer.not_json_page().unwrap_or_default()
                    ),
                }));
            };
            if let Some(Json::Array(items)) = page.get("value") {
                rules.extend(items.iter().cloned());
            }
            if let Some(Json::Str(link)) = page.get("@odata.nextLink")
                && !link.is_empty()
            {
                next = Some(links.follow(link).map_err(refused)?);
            }
        }
        Ok(rules)
    }

    /// Runs an advanced hunting query over the request's window
    /// (`DefenderQueryRunner.run`). *now* is the moment the 30-day retention
    /// is counted from.
    #[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
    pub async fn run(
        &self,
        cx: TenantContext<'_>,
        request: &QueryRequest,
        now: jiff::Timestamp,
    ) -> Result<QueryOutcome, ConnectorError> {
        let tenant = &cx.tenant.label.tenant;
        let oldest = now
            .checked_sub(jiff::SignedDuration::from_hours(24 * MAX_LOOKBACK_DAYS))
            .unwrap_or(now);
        if request.window.start < oldest {
            return Err(ConnectorError::refused(
                PLATFORM,
                tenant,
                format!(
                    "advanced hunting keeps {MAX_LOOKBACK_DAYS} days of data: start the window after {}",
                    utc_z(oldest)
                ),
                None,
            ));
        }
        for key in ["tenant_id", "client_id", "client_secret"] {
            cx.tenant.secret(key)?;
        }
        let sent = kql_with_limit(&request.text, request.limit);
        let mut body = Object::new();
        body.insert("Query".into(), Json::Str(sent.clone()));
        body.insert(
            "Timespan".into(),
            Json::Str(format!(
                "{}/{}",
                utc_z(request.window.start),
                utc_z(request.window.end)
            )),
        );
        let answer = self
            .graph(
                cx,
                crate::transport::Method::POST,
                HUNTING_QUERY_ENDPOINT,
                Some(&Json::Object(body)),
            )
            .await
            .map_err(|error| error.into_connector(tenant))?;
        if answer.status != 200 {
            let mut message = format!(
                "Graph refused the hunting query on {tenant} (HTTP {})",
                answer.status
            );
            if answer.status == 403 {
                message.push_str(": the app registration needs ThreatHunting.Read.All");
            }
            let detail = answer
                .not_json_detail()
                .unwrap_or_else(|| error_message(&answer));
            if answer.status == 403 {
                // The app registration's permission, not the query: the
                // tenant's failure (#1658, E8).
                return Err(ConnectorError::authentication(
                    PLATFORM,
                    tenant,
                    format!("{message}: {detail}"),
                ));
            }
            return Err(ConnectorError::refused(
                PLATFORM,
                tenant,
                message,
                Some(detail),
            ));
        }
        let Some(body) = answer.json() else {
            return Err(ConnectorError::refused(
                PLATFORM,
                tenant,
                format!("Graph did not answer the hunting query on {tenant} with JSON"),
                answer.not_json_detail(),
            ));
        };
        let schema = first_present(&body, "schema", "Schema");
        let columns: Vec<QueryColumn> = match schema {
            Some(Json::Array(items)) => items
                .iter()
                .filter_map(|column| {
                    column.as_object()?;
                    let name = first_filled(column.get("name"), column.get("Name"));
                    let kind = first_filled(column.get("type"), column.get("Type"));
                    Some(QueryColumn {
                        name: name.map_or_else(|| "null".to_owned(), Json::to_text),
                        kind: kind.map(Json::to_text),
                    })
                })
                .collect(),
            _ => Vec::new(),
        };
        let rows: Vec<Row> = match first_present(&body, "results", "Results") {
            Some(Json::Array(items)) => items
                .iter()
                .filter(|row| row.is_filled())
                .filter_map(Json::as_object)
                .cloned()
                .collect(),
            _ => Vec::new(),
        };
        let truncated = rows.len() > request.limit;
        Ok(QueryOutcome {
            columns,
            rows: rows.into_iter().take(request.limit).collect(),
            truncated,
            partial: false,
            warnings: Vec::new(),
            vendor_query_id: None,
            sent: (sent != request.text.trim()).then_some(sent),
            language: Some("kql".into()),
        })
    }

    /// `validate query --live`'s check of one rule query: a search for one
    /// row, then the columns a custom detection needs
    /// (`MicrosoftDefenderQueryValidator.inspect`).
    pub async fn check(
        &self,
        cx: TenantContext<'_>,
        request: &QueryRequest,
        now: jiff::Timestamp,
    ) -> Result<LiveCheck, ConnectorError> {
        let result = self.run(cx, &request.for_check(), now).await?;
        let returned: Vec<&str> = result.columns.iter().map(|c| c.name.as_str()).collect();
        let missing = missing_required_column_groups(&request.text, &returned);
        let errors = if missing.is_empty() {
            Vec::new()
        } else {
            vec![format!("the query's output lacks {}", missing.join("; "))]
        };
        Ok(LiveCheck {
            result: Some(result),
            errors,
            warnings: Vec::new(),
        })
    }
}

/// *body* as `requests`' `json=` writes it.
fn json_body(cx: TenantContext<'_>, body: &Json) -> Result<Vec<u8>, ConnectorError> {
    serde_json::to_vec(body).map_err(|error| ConnectorError::Setup {
        platform: cx.tenant.label.platform.clone(),
        tenant: cx.tenant.label.tenant.clone(),
        message: format!("the request body cannot be written: {error}"),
    })
}

/// `_error_body`: the JSON of an error answer, else its text, else a note.
fn error_body_value(answer: &Answer) -> Json {
    answer.quotable_json().unwrap_or_else(|| {
        let text = answer.text();
        if text.is_empty() {
            Json::Str(format!("(empty body, HTTP {})", answer.status))
        } else {
            Json::Str(text)
        }
    })
}

/// `str(_error_body(response))`.
fn error_body(answer: &Answer) -> String {
    Json::to_text(&error_body_value(answer))
}

/// `str(_error_message(response))`: Graph's `error.message`, or the body.
fn error_message(answer: &Answer) -> String {
    let body = error_body_value(answer);
    let message = body
        .get("error")
        .filter(|error| error.as_object().is_some())
        .and_then(|error| error.get("message"))
        .filter(|message| message.is_filled());
    Json::to_text(message.unwrap_or(&body))
}

/// `body.get(a, body.get(b, None))`.
fn first_present<'j>(body: &'j Json, first: &str, second: &str) -> Option<&'j Json> {
    body.get(first).or_else(|| body.get(second))
}

/// `first` when it holds a value, else `second` when it does.
fn first_filled<'j>(first: Option<&'j Json>, second: Option<&'j Json>) -> Option<&'j Json> {
    first
        .filter(|value| value.is_filled())
        .or(second)
        .filter(|value| value.is_filled())
}

pub use opentide_schema::objects::platform::microsoft_defender::required_columns::{
    DEFENDER_XDR_TABLES, defender_xdr_tables_in_query, missing_required_column_groups,
    required_column_groups,
};

impl MicrosoftDefender {
    /// What a deploy does before its first rule: the Entra ID sign-in
    /// ([`Deployer::open`], and [`Prober::probe`]'s first step).
    async fn open_tenant(&self, cx: TenantContext<'_>) -> Result<(), ConnectorError> {
        self.token(cx)
            .await
            .map(|_| ())
            .map_err(|error| error.into_connector(&cx.tenant.label.tenant))
    }
}

impl Prober for MicrosoftDefender {
    /// Opens the tenant as a deploy does (the Entra ID sign-in), then reads
    /// the first page of custom detection rules: `GET .../detectionRules`, the
    /// collection URL a listing starts from (the recorded listing's), which
    /// writes nothing and needs the token. No `$top`: no recording shows Graph
    /// accepting it on this beta collection, and a 400 would fail every tenant.
    fn probe<'a>(
        &'a self,
        cx: TenantContext<'a>,
    ) -> BoxFuture<'a, Result<(), crate::connector::DeployError>> {
        crate::connector::probing(async move {
            let tenant = &cx.tenant.label.tenant;
            self.open_tenant(cx).await?;
            let answer = self
                .graph(
                    cx,
                    crate::transport::Method::GET,
                    DETECTION_RULES_ENDPOINT,
                    None,
                )
                .await
                .map_err(|error| error.into_connector(tenant))?;
            probe_verdict(
                PLATFORM,
                tenant,
                "reading the detection rules",
                answer.status,
            )
        })
    }
}

/// The event of a rule created after its `PATCH` found none.
pub const RULE_CREATED: &str = "microsoft_defender_rule_created";
/// The event of a rule updated in place, disabled included.
pub const RULE_UPDATED: &str = "microsoft_defender_rule_updated";
/// The event of a rule deleted.
pub const RULE_DELETED: &str = "microsoft_defender_rule_deleted";
/// The warning of a DISABLEMENT that found no rule with the id on the
/// tenant: nothing is created (microsoft-defender-1.0, Diagnostics).
pub const RULE_ABSENT: &str = "microsoft_defender_rule_absent";
/// The failure of a create Graph refused with `409` while no rule has the
/// id: another rule most likely holds the display name or the alert title
/// (one an earlier opentide release created, under its bare uuid or in 0.x,
/// or one created by hand), which Graph keeps reserved for a disabled rule
/// too (#1886).
pub const RULE_CONFLICT: &str = "microsoft_defender_rule_conflict";

/// What one rule's deploy did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// Created: `POST` after a `404` on `PATCH`.
    Created,
    /// Updated: `PATCH`, the first or the one after a `409` on the `POST`.
    Updated,
    /// A DISABLEMENT's `PATCH` answered `404`: nothing to disable.
    Absent,
    /// Deleted: `DELETE` answered `2xx`.
    Deleted,
}

impl Sent {
    /// The event `opentide deploy` logs for it.
    pub const fn event(self) -> &'static str {
        match self {
            Self::Created => RULE_CREATED,
            Self::Updated => RULE_UPDATED,
            Self::Absent => RULE_ABSENT,
            Self::Deleted => RULE_DELETED,
        }
    }
}

/// Whether an answer is a success.
const fn succeeded(status: u16) -> bool {
    status >= 200 && status < 300
}

impl MicrosoftDefender {
    /// A rule's failure on the tenant: Graph refused `verb` with `answer`.
    fn refused(
        cx: TenantContext<'_>,
        verb: &str,
        id: &str,
        answer: &Answer,
    ) -> crate::connector::DeployError {
        let tenant = &cx.tenant.label.tenant;
        crate::connector::DeployError::rule(
            crate::connector::DeployFailure::new(
                "tenant_refused",
                format!(
                    "Graph refused to {verb} detection rule {id} on tenant {tenant}: HTTP {} ({})",
                    answer.status,
                    error_message(answer)
                ),
            )
            .with_status(answer.status)
            .with_field("platform", PLATFORM)
            .with_field("tenant", tenant.as_str())
            .with_field("detail", error_body(answer)),
        )
    }

    /// One Graph call of a deploy; a failure to send fails the tenant.
    async fn send(
        &self,
        cx: TenantContext<'_>,
        method: crate::transport::Method,
        url: &str,
        body: Option<&Json>,
    ) -> Result<Answer, crate::connector::DeployError> {
        self.graph(cx, method, url, body)
            .await
            .map_err(|error| error.into_connector(&cx.tenant.label.tenant).into())
    }

    /// An active status (microsoft-defender-1.0, Deploy): `PATCH
    /// {base}/{id}` with *body*; on `404`, `POST {base}` with the body and
    /// `id`; a `409` on that `POST` (the rule was created meanwhile) gets one
    /// more `PATCH`, never another `POST`. When that `PATCH` answers `404`
    /// too, no rule has the id and the `409` was another rule's display
    /// name: [`RULE_CONFLICT`]. *id* is the Defender rule id
    /// ([`opentide_compile::microsoft_defender::rule_id_of`]).
    pub async fn upsert(
        &self,
        cx: TenantContext<'_>,
        id: &str,
        body: &Json,
    ) -> Result<Sent, crate::connector::DeployError> {
        use crate::transport::Method;
        let url = opentide_compile::microsoft_defender::rule_url(id);
        let answer = self.send(cx, Method::PATCH, &url, Some(body)).await?;
        if succeeded(answer.status) {
            return Ok(Sent::Updated);
        }
        if answer.status != 404 {
            return Err(Self::refused(cx, "update", id, &answer));
        }
        let create = opentide_compile::microsoft_defender::create_body(id, body);
        let answer = self
            .send(cx, Method::POST, DETECTION_RULES_ENDPOINT, Some(&create))
            .await?;
        if succeeded(answer.status) {
            return Ok(Sent::Created);
        }
        if answer.status != 409 {
            return Err(Self::refused(cx, "create", id, &answer));
        }
        let conflict = answer;
        let answer = self.send(cx, Method::PATCH, &url, Some(body)).await?;
        if succeeded(answer.status) {
            return Ok(Sent::Updated);
        }
        if answer.status == 404 {
            return Err(Self::conflict(cx, id, &conflict));
        }
        Err(Self::refused(cx, "update", id, &answer))
    }

    /// [`RULE_CONFLICT`]: Graph refused to create *id* with *answer*'s `409`,
    /// and no rule has the id.
    fn conflict(cx: TenantContext<'_>, id: &str, answer: &Answer) -> crate::connector::DeployError {
        let tenant = &cx.tenant.label.tenant;
        crate::connector::DeployError::rule(
            crate::connector::DeployFailure::new(
                RULE_CONFLICT,
                format!(
                    "Graph refused to create detection rule {id} on tenant {tenant}: HTTP {} \
                     ({}). No rule has this id, so another rule most likely holds its \
                     display name or alert title: one an earlier opentide release created \
                     (under the bare uuid in 1.0.0, or in 0.x), or one created by hand. \
                     Graph keeps them reserved for a disabled rule too: delete that rule in \
                     the Defender portal (or rename both its name and its alert title), \
                     then deploy again",
                    answer.status,
                    error_message(answer)
                ),
            )
            .with_status(answer.status)
            .with_field("platform", PLATFORM)
            .with_field("tenant", tenant.as_str())
            .with_field("detail", error_body(answer)),
        )
    }

    /// A DISABLEMENT: `PATCH {base}/{id}` with *body* (`status: disabled`);
    /// a `404` creates nothing and is [`Sent::Absent`].
    pub async fn disable(
        &self,
        cx: TenantContext<'_>,
        id: &str,
        body: &Json,
    ) -> Result<Sent, crate::connector::DeployError> {
        let url = opentide_compile::microsoft_defender::rule_url(id);
        let answer = self
            .send(cx, crate::transport::Method::PATCH, &url, Some(body))
            .await?;
        match answer.status {
            status if succeeded(status) => Ok(Sent::Updated),
            404 => Ok(Sent::Absent),
            _ => Err(Self::refused(cx, "disable", id, &answer)),
        }
    }

    /// A DELETION: `DELETE {base}/{id}`. A `404` (the rule already gone) is a
    /// failure with status `404`, which `opentide deploy` reports as skipped.
    pub async fn delete(
        &self,
        cx: TenantContext<'_>,
        id: &str,
    ) -> Result<Sent, crate::connector::DeployError> {
        let url = opentide_compile::microsoft_defender::rule_url(id);
        let answer = self
            .send(cx, crate::transport::Method::DELETE, &url, None)
            .await?;
        if succeeded(answer.status) {
            return Ok(Sent::Deleted);
        }
        Err(Self::refused(cx, "delete", id, &answer))
    }
}

impl Deployer for MicrosoftDefender {
    /// The Entra ID sign-in, once: the first rule's request reuses its token.
    fn open<'a>(
        &'a self,
        cx: TenantContext<'a>,
    ) -> BoxFuture<'a, Result<(), crate::connector::DeployError>> {
        crate::connector::opening(self.open_tenant(cx))
    }

    /// One rule by its Defender rule id
    /// ([`opentide_compile::microsoft_defender::rule_id_of`] of
    /// `request.rule_id`, the rule's uuid or that id), with the compiled
    /// update body: [`MicrosoftDefender::upsert`] for a create or an update,
    /// [`MicrosoftDefender::disable`], [`MicrosoftDefender::delete`]. No id
    /// is recorded: `remote_id` is the rule id while the rule exists.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, crate::connector::DeployError>> {
        Box::pin(async move {
            let tenant = cx.tenant.label.tenant.clone();
            // A token Entra ID did not issue fails the tenant, whatever its
            // answer: the tenant signs in first (on its kept token, if any).
            self.token(cx).await.map_err(|error| {
                let mut failed = crate::connector::DeployError::from(error.into_connector(&tenant));
                failed.scope = crate::connector::DeployScope::Tenant;
                failed
            })?;
            let id = opentide_compile::microsoft_defender::rule_id_of(&request.rule_id);
            let body = || -> Result<Json, crate::connector::DeployError> {
                serde_json::from_slice(&request.body).map_err(|error| {
                    ConnectorError::Setup {
                        platform: PLATFORM.into(),
                        tenant: tenant.clone(),
                        message: format!("the compiled rule is not JSON: {error}"),
                    }
                    .into()
                })
            };
            let sent = match request.operation {
                Operation::Create | Operation::Update => self.upsert(cx, &id, &body()?).await?,
                Operation::Disable => self.disable(cx, &id, &body()?).await?,
                Operation::Delete => self.delete(cx, &id).await?,
            };
            let mut warnings = Vec::new();
            if sent == Sent::Absent {
                warnings.push(DeployWarning::new(
                    RULE_ABSENT,
                    format!("rule {id} is not on tenant '{tenant}': nothing to disable"),
                ));
            }
            Ok(DeployOutcome {
                events: vec![
                    crate::connector::DeployEvent::new(sent.event())
                        .with_field("rule_id", id.clone()),
                ],
                remote_id: matches!(sent, Sent::Created | Sent::Updated).then_some(id),
                operation: match sent {
                    Sent::Created => Operation::Create,
                    Sent::Deleted => Operation::Delete,
                    Sent::Updated | Sent::Absent => request.operation,
                },
                warnings,
            })
        })
    }
}

impl QueryRunner for MicrosoftDefender {
    /// An advanced hunting query over the request's window; the 30-day
    /// retention is counted from now.
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        Box::pin(
            async move { MicrosoftDefender::run(self, cx, request, jiff::Timestamp::now()).await },
        )
    }
}

impl LiveValidator for MicrosoftDefender {
    /// A search for one row over the request's window, then the columns a
    /// custom detection needs.
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        Box::pin(async move { self.check(cx, request, jiff::Timestamp::now()).await })
    }
}

impl Platform for MicrosoftDefender {
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

    #[test]
    fn graph_errors_do_not_quote_the_bearer() {
        use crate::answer::{TEST_BEARER, answer_to_bearer};
        let answer = answer_to_bearer(&format!(
            r#"{{"error":{{"code":"X","message":"bad {TEST_BEARER}"}}}}"#
        ));
        assert_eq!(error_message(&answer), "bad ***");
        let shown = error_body(&answer);
        assert!(
            shown.contains("bad ***") && !shown.contains(TEST_BEARER),
            "{shown}"
        );
    }
}
