//! Microsoft Defender for Endpoint through Microsoft Graph (UC-4.2, #832):
//! `platforms/defender_for_endpoint/client.py` (`DefenderForEndpointService`),
//! the deploy calls its `deployer.py` makes, `runner.py` (advanced hunting)
//! and `validator.py` (the columns a custom detection needs), request for
//! request.
//!
//! The client signs in to Entra ID with the tenant's app registration
//! ([`crate::entra`]: `tenant_id`, `client_id`, `client_secret`, scope
//! Graph's), keeps the token until it is due for renewal (a `401` gets one
//! new token and one resend), and sends every call to Graph's
//! beta security API with the bearer token and `Content-Type:
//! application/json`. Bodies are the compiled rule (`opentide-compile`
//! `defender::body`), sent as compact JSON.

use std::sync::Arc;

use opentide_compile::json::{Json, Object};

use crate::answer::Answer;
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, DeployWarning, Deployer, LiveCheck, LiveValidator,
    Operation, Platform, QueryColumn, QueryOutcome, QueryRequest, QueryRunner, Row, TenantContext,
    kql_code, kql_with_limit, utc_z,
};
use crate::entra::CredentialNames;
use crate::error::ConnectorError;
use crate::retry::RetryPolicy;
use crate::text::json_text;
use crate::token::TokenCache;
use crate::{HttpSettings, Secret};

/// The platform's identifier.
pub const PLATFORM: &str = "defender_for_endpoint";

/// The tenant setup's names for the app registration.
pub const CREDENTIALS: CredentialNames = CredentialNames {
    tenant_id: "tenant_id",
    client_id: "client_id",
    client_secret: "client_secret",
};
/// Graph's security API.
pub const GRAPH_API_ENDPOINT: &str = "https://graph.microsoft.com/beta/security";
/// The custom detection rules collection.
pub const DETECTION_RULES_ENDPOINT: &str =
    "https://graph.microsoft.com/beta/security/rules/detectionRules";
/// Advanced hunting.
pub const HUNTING_QUERY_ENDPOINT: &str =
    "https://graph.microsoft.com/beta/security/runHuntingQuery";
/// The scope the client credentials are granted for.
pub const SCOPE: &str = "https://graph.microsoft.com/.default";

/// Advanced hunting keeps 30 days of data; Graph refuses a longer timespan.
pub const MAX_LOOKBACK_DAYS: i64 = 30;

/// Response actions the safer configuration drops: they map user
/// identifiers a query may not return.
pub const RISKY_RESPONSE_ACTIONS: [&str; 3] = [
    "#microsoft.graph.security.markUserAsCompromisedResponseAction",
    "#microsoft.graph.security.disableUserResponseAction",
    "#microsoft.graph.security.forceUserPasswordResetResponseAction",
];

/// The HTTP settings of a Defender tenant: 120 s and the connectors'
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

/// The warning of a rule created with the safer configuration
/// ([`Created::partial`]): the event `opentide deploy` logs for it.
pub const PARTIAL_DEPLOYMENT: &str =
    "this_is_a_partial_deployment_check_the_mde_gui_to_see_the_availa";

/// A rule Graph created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Created {
    /// Graph's id of the rule, kept in deployment state.
    pub id: i64,
    /// Created with the safer configuration after the full one was refused
    /// (`DEPLOYMENT_WARNING_RAISED`): check the impacted assets in the portal.
    pub partial: bool,
}

/// The Defender for Endpoint connector. A tenant's token serves every call
/// until it is due for renewal.
#[derive(Debug, Default)]
pub struct Defender {
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

impl Defender {
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

    /// Creates a custom detection rule from its compiled *body*
    /// (`create_detection_rule`). When Graph refuses it, it is sent again
    /// with the safer configuration (device impacted asset, no user response
    /// action) to the same collection.
    pub async fn create_rule(
        &self,
        cx: TenantContext<'_>,
        body: &Json,
    ) -> Result<Created, DefenderError> {
        let tenant = &cx.tenant.label.tenant;
        let answer = self
            .graph(
                cx,
                crate::transport::Method::POST,
                DETECTION_RULES_ENDPOINT,
                Some(body),
            )
            .await?;
        if answer.status == 201 {
            return Ok(Created {
                id: created_id(&answer, tenant)?,
                partial: false,
            });
        }
        let safer = safer_configuration(body);
        let answer = self
            .graph(
                cx,
                crate::transport::Method::POST,
                DETECTION_RULES_ENDPOINT,
                Some(&safer),
            )
            .await?;
        if answer.status == 201 {
            return Ok(Created {
                id: created_id(&answer, tenant)?,
                partial: true,
            });
        }
        Err(DefenderError::Refused {
            message: format!(
                "Failed to create detection rule in tenant {tenant} with the safer configuration - Error Code {}",
                answer.status
            ),
            context: Some(error_body(&answer)),
        })
    }

    /// Every custom detection rule of the tenant, across Graph's pages
    /// (`DefenderForEndpointImporter.list_rules`, UC-4.4b): `@odata.nextLink`
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
                        "Listing Defender for Endpoint detection rules on tenant {} failed with \
                         HTTP {} {reason}",
                        cx.tenant.label.tenant, answer.status
                    ),
                    context: None,
                });
            }
            let page = answer.json().unwrap_or(Json::Null);
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

    /// Replaces rule *rule_id* with *body* (`update_detection_rule`).
    pub async fn update_rule(
        &self,
        cx: TenantContext<'_>,
        body: &Json,
        rule_id: &str,
    ) -> Result<(), DefenderError> {
        let url = format!("{DETECTION_RULES_ENDPOINT}/{rule_id}");
        let answer = self
            .graph(cx, crate::transport::Method::PATCH, &url, Some(body))
            .await?;
        if answer.status == 200 {
            return Ok(());
        }
        Err(DefenderError::Refused {
            message: format!(
                "Failed to update detection rule with id {rule_id} in tenant {} ({url}) - Error Code {}",
                cx.tenant.label.tenant, answer.status
            ),
            context: Some(error_body(&answer)),
        })
    }

    /// Deletes rule *rule_id* (`delete_detection_rule`).
    pub async fn delete_rule(
        &self,
        cx: TenantContext<'_>,
        rule_id: &str,
    ) -> Result<(), DefenderError> {
        let url = format!("{DETECTION_RULES_ENDPOINT}/{rule_id}");
        let answer = self
            .graph(cx, crate::transport::Method::DELETE, &url, None)
            .await?;
        if answer.status == 204 {
            return Ok(());
        }
        Err(DefenderError::Refused {
            message: format!(
                "Failed to delete detection rule with id {rule_id} in tenant {}",
                cx.tenant.label.tenant
            ),
            context: None,
        })
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
                        name: name.map_or_else(|| "null".to_owned(), json_text),
                        kind: kind.map(json_text),
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
    /// (`DefenderForEndpointQueryValidator.inspect`).
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

/// `int(response.json()["id"])`.
fn created_id(answer: &Answer, tenant: &str) -> Result<i64, DefenderError> {
    let id = answer.json().and_then(|body| match body.get("id") {
        Some(Json::Str(text)) => text.trim().parse::<i64>().ok(),
        Some(Json::Int(id)) => Some(*id),
        _ => None,
    });
    id.ok_or_else(|| DefenderError::Refused {
        message: format!("Graph created a rule in tenant {tenant} without a numeric id"),
        context: Some(answer.text()),
    })
}

/// The rule reconfigured to a minimal but functional state
/// (`_safer_configuation`): one device impacted asset, mapped by `deviceId`,
/// and no response action that maps a user.
pub fn safer_configuration(body: &Json) -> Json {
    let mut rule = body.clone();
    let Json::Object(top) = &mut rule else {
        return rule;
    };
    let Some(Json::Object(action)) = top.get_mut("detectionAction") else {
        return rule;
    };
    if let Some(Json::Object(template)) = action.get_mut("alertTemplate")
        && template.get("impactedAssets").is_some_and(Json::is_filled)
    {
        let mut device = Object::new();
        device.insert(
            "@odata.type".into(),
            "#microsoft.graph.security.impactedDeviceAsset".into(),
        );
        device.insert("identifier".into(), "deviceId".into());
        template.insert(
            "impactedAssets".into(),
            Json::Array(vec![Json::Object(device)]),
        );
    }
    if let Some(Json::Array(actions)) = action.get_mut("responseActions")
        && !actions.is_empty()
    {
        actions.retain(|action| {
            !action
                .get("@odata.type")
                .and_then(Json::as_str)
                .is_some_and(|kind| RISKY_RESPONSE_ACTIONS.contains(&kind))
        });
    }
    rule
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
    json_text(&error_body_value(answer))
}

/// `str(_error_message(response))`: Graph's `error.message`, or the body.
fn error_message(answer: &Answer) -> String {
    let body = error_body_value(answer);
    let message = body
        .get("error")
        .filter(|error| error.as_object().is_some())
        .and_then(|error| error.get("message"))
        .filter(|message| message.is_filled());
    json_text(message.unwrap_or(&body))
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

/// The Defender XDR advanced hunting tables a custom detection names, with
/// their family (`DEFENDER_XDR_TABLES`).
pub const DEFENDER_XDR_TABLES: [(&str, &str); 33] = [
    ("DeviceEvents", "endpoint"),
    ("DeviceFileCertificateInfo", "endpoint"),
    ("DeviceFileEvents", "endpoint"),
    ("DeviceImageLoadEvents", "endpoint"),
    ("DeviceInfo", "endpoint"),
    ("DeviceLogonEvents", "endpoint"),
    ("DeviceNetworkEvents", "endpoint"),
    ("DeviceNetworkInfo", "endpoint"),
    ("DeviceProcessEvents", "endpoint"),
    ("DeviceRegistryEvents", "endpoint"),
    ("AlertEvidence", "alert"),
    ("AlertInfo", "alert"),
    ("CampaignInfo", "xdr"),
    ("EmailAttachmentInfo", "xdr"),
    ("EmailEvents", "xdr"),
    ("EmailPostDeliveryEvents", "xdr"),
    ("EmailUrlInfo", "xdr"),
    ("FileMaliciousContentInfo", "xdr"),
    ("MessageEvents", "xdr"),
    ("MessagePostDeliveryEvents", "xdr"),
    ("MessageUrlInfo", "xdr"),
    ("UrlClickEvents", "xdr"),
    ("AADSignInEventsBeta", "xdr"),
    ("AADSpnSignInEventsBeta", "xdr"),
    ("CloudAppEvents", "xdr"),
    ("EntraIdSignInEvents", "xdr"),
    ("EntraIdSpnSignInEvents", "xdr"),
    ("IdentityAccountInfo", "xdr"),
    ("IdentityDirectoryEvents", "xdr"),
    ("IdentityInfo", "xdr"),
    ("IdentityLogonEvents", "xdr"),
    ("IdentityQueryEvents", "xdr"),
    ("OAuthAppInfo", "xdr"),
];

const TIMESTAMP_COLUMNS: [&str; 2] = ["Timestamp", "TimeGenerated"];
const IMPACTED_ASSET_IDENTIFIER_COLUMNS: [&str; 14] = [
    "DeviceId",
    "DeviceName",
    "RemoteDeviceName",
    "RecipientEmailAddress",
    "SenderFromAddress",
    "SenderMailFromAddress",
    "SenderObjectId",
    "RecipientObjectId",
    "AccountObjectId",
    "AccountSid",
    "AccountUpn",
    "InitiatingProcessAccountSid",
    "InitiatingProcessAccountUpn",
    "InitiatingProcessAccountObjectId",
];

fn is_word(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// The Defender XDR tables *query* names (`defender_xdr_tables_in_query`).
///
/// Comments and string literals are blanked with [`kql_code`], which reads a
/// string before a `//` inside it: `let u = "http://x"; DeviceEvents` names
/// `DeviceEvents`.
pub fn defender_xdr_tables_in_query(query: &str) -> Vec<String> {
    let query = kql_code(query);
    let mut tables: Vec<String> = Vec::new();
    let preceded_ok = |at: usize| {
        query[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word(c) && c != '.')
    };
    for (table, _) in DEFENDER_XDR_TABLES {
        let found = query.match_indices(table).any(|(at, _)| {
            let followed_ok = query[at + table.len()..]
                .chars()
                .next()
                .is_none_or(|c| !is_word(c));
            preceded_ok(at) && followed_ok
        });
        if found {
            tables.push(table.to_owned());
        }
    }
    let mut from = 0;
    while let Some(offset) = query[from..].find("Observation") {
        let at = from + offset;
        let rest = &query[at + "Observation".len()..];
        let tail: usize = rest
            .chars()
            .take_while(|&c| is_word(c))
            .map(char::len_utf8)
            .sum();
        if preceded_ok(at) && tail > 0 {
            let name = &query[at..at + "Observation".len() + tail];
            if name != "ObservationId" && !tables.iter().any(|known| known == name) {
                tables.push(name.to_owned());
            }
            from = at + "Observation".len() + tail;
        } else {
            from = at + "Observation".len();
        }
    }
    tables.sort();
    tables
}

/// The column groups a custom detection's output needs, each an OR group
/// (`required_column_groups`).
pub fn required_column_groups(query: &str) -> Vec<Vec<&'static str>> {
    let tables = defender_xdr_tables_in_query(query);
    let categories: Vec<&str> = tables
        .iter()
        .map(|table| {
            if table.starts_with("Observation") {
                "observation"
            } else {
                DEFENDER_XDR_TABLES
                    .iter()
                    .find(|(name, _)| name == table)
                    .map_or("xdr", |(_, category)| *category)
            }
        })
        .collect();
    let has = |category: &str| categories.contains(&category);
    let mut groups: Vec<Vec<&'static str>> = vec![if categories.is_empty() {
        TIMESTAMP_COLUMNS.to_vec()
    } else {
        vec!["Timestamp"]
    }];
    if has("endpoint") {
        groups.push(vec!["DeviceId"]);
        groups.push(vec!["ReportId"]);
    }
    if has("observation") {
        groups.push(vec!["ObservationId"]);
    }
    if (has("xdr") || categories.is_empty()) && !groups.iter().any(|group| group == &["ReportId"]) {
        groups.push(vec!["ReportId"]);
    }
    if !has("endpoint") {
        groups.push(IMPACTED_ASSET_IDENTIFIER_COLUMNS.to_vec());
    }
    groups
}

/// The groups none of whose columns *returned* holds, each as `A or B`
/// (`missing_required_column_groups`).
pub fn missing_required_column_groups(query: &str, returned: &[&str]) -> Vec<String> {
    required_column_groups(query)
        .into_iter()
        .filter(|group| !group.iter().any(|column| returned.contains(column)))
        .map(|mut group| {
            group.sort_unstable();
            group.join(" or ")
        })
        .collect()
}

impl Deployer for Defender {
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        Box::pin(async move {
            let answer = |error: DefenderError| match error {
                DefenderError::Connector(error) => error,
                other => ConnectorError::Answer {
                    platform: PLATFORM.into(),
                    tenant: cx.tenant.label.tenant.clone(),
                    address: "https://graph.microsoft.com".into(),
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
            let mut warnings = Vec::new();
            let remote_id = match request.operation {
                Operation::Create => {
                    let created = self.create_rule(cx, &body()?).await.map_err(answer)?;
                    if created.partial {
                        warnings.push(DeployWarning::new(
                            PARTIAL_DEPLOYMENT,
                            "the rule was created with a safer configuration after Defender \
                             refused the full one: check the impacted assets in the Defender \
                             portal",
                        ));
                    }
                    Some(created.id.to_string())
                }
                // A disabled rule is the rule with `isEnabled` false.
                Operation::Update | Operation::Disable => {
                    self.update_rule(cx, &body()?, &request.rule_id)
                        .await
                        .map_err(answer)?;
                    Some(request.rule_id.clone())
                }
                Operation::Delete => {
                    self.delete_rule(cx, &request.rule_id)
                        .await
                        .map_err(answer)?;
                    None
                }
            };
            Ok(DeployOutcome {
                remote_id,
                operation: request.operation,
                warnings,
            })
        })
    }
}

impl QueryRunner for Defender {
    /// An advanced hunting query over the request's window; the 30-day
    /// retention is counted from now.
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        Box::pin(async move { Defender::run(self, cx, request, jiff::Timestamp::now()).await })
    }
}

impl LiveValidator for Defender {
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

impl Platform for Defender {
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

    #[test]
    fn a_double_slash_in_a_string_does_not_hide_the_table() {
        // `validate query --live` passed this query: the URL's `//` blanked
        // the rest of the query as a comment, so no table was found and the
        // endpoint columns were not required.
        let returned = ["Timestamp", "ReportId", "DeviceName"];
        assert_eq!(
            missing_required_column_groups(
                "let u = \"http://x\"; DeviceNetworkEvents | where RemoteUrl == u \
                 | project Timestamp, ReportId, DeviceName",
                &returned
            ),
            ["DeviceId"]
        );
        // A verbatim string has no escapes, and doubles a quote inside it.
        assert_eq!(
            missing_required_column_groups(
                r#"let u = @"\\host//share\"; DeviceFileEvents | project Timestamp, ReportId, DeviceName"#,
                &returned
            ),
            ["DeviceId"]
        );
        assert_eq!(
            defender_xdr_tables_in_query(
                r#"let p = @'C:\'; let q = @"//a""\"; EmailEvents | where 'b//' != p"#
            ),
            ["EmailEvents"]
        );
        // An escaped quote does not end a string; a comment still hides a table.
        assert_eq!(
            defender_xdr_tables_in_query(r#"print "a\"// DeviceEvents" // AlertInfo"#),
            Vec::<String>::new()
        );
        // A multi-line string has no escapes and ends at its own chord.
        assert_eq!(
            missing_required_column_groups(
                "let s = ```http://x```; DeviceEvents | project Timestamp, ReportId, DeviceName",
                &returned
            ),
            ["DeviceId"]
        );
        assert_eq!(
            defender_xdr_tables_in_query("let s = ~~~a```//~~~; EmailEvents | take 1"),
            ["EmailEvents"]
        );
        // Kusto has no block comments: a table inside `/* */` is read as
        // code, so its columns are required (the check fails closed).
        assert_eq!(
            defender_xdr_tables_in_query("/* DeviceEvents */ print 1"),
            ["DeviceEvents"]
        );
    }

    #[test]
    fn column_groups_follow_the_tables_the_query_names() {
        assert_eq!(
            missing_required_column_groups(
                "DeviceProcessEvents | project Timestamp, DeviceName",
                &["Timestamp", "DeviceName"]
            ),
            ["DeviceId", "ReportId"]
        );
        // A table named in a comment or a string is not one the query reads.
        assert_eq!(
            defender_xdr_tables_in_query("// EmailEvents\nT | where x == 'DeviceEvents'"),
            Vec::<String>::new()
        );
        assert_eq!(
            defender_xdr_tables_in_query("ObservationFoo | join ObservationId x.DeviceEvents"),
            ["ObservationFoo"]
        );
        assert_eq!(
            missing_required_column_groups("print 1", &[]),
            [
                "TimeGenerated or Timestamp",
                "ReportId",
                "AccountObjectId or AccountSid or AccountUpn or DeviceId or DeviceName or InitiatingProcessAccountObjectId or InitiatingProcessAccountSid or InitiatingProcessAccountUpn or RecipientEmailAddress or RecipientObjectId or RemoteDeviceName or SenderFromAddress or SenderMailFromAddress or SenderObjectId"
            ]
        );
    }
}
