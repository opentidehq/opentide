//! Microsoft Defender for Endpoint through Microsoft Graph (UC-4.2, #832):
//! `platforms/defender_for_endpoint/client.py` (`DefenderForEndpointService`),
//! the deploy calls its `deployer.py` makes, `runner.py` (advanced hunting)
//! and `validator.py` (the columns a custom detection needs), request for
//! request.
//!
//! The client signs in once per tenant with the app registration's client
//! credentials (Entra ID's token endpoint), then sends every call to Graph's
//! beta security API with the bearer token and `Content-Type:
//! application/json`. Bodies are the compiled rule (`opentide-compile`
//! `defender::body`) written as `json.dumps` writes them.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use opentide_compile::json::{Json, Object};

use crate::answer::Answer;
use crate::body::python_json;
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, LiveCheck, LiveValidator, Operation,
    Platform, QueryColumn, QueryOutcome, QueryRequest, QueryRunner, Row, TenantContext,
    kql_with_limit, utc_z,
};
use crate::error::ConnectorError;
use crate::python::python_str;
use crate::{HttpSettings, Secret, TenantLabel};

/// The platform's identifier.
pub const PLATFORM: &str = "defender_for_endpoint";

/// Entra ID's token endpoint; `{tenant_id}` is the directory.
pub const TOKEN_ENDPOINT: &str = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token";
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

/// The HTTP settings of a Defender tenant: `TenantSession`'s, no retries.
pub fn http_settings() -> HttpSettings {
    HttpSettings::default()
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
        /// The call and the tenant, as the Python client logs it.
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

/// A rule Graph created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Created {
    /// Graph's id of the rule, kept in deployment state.
    pub id: i64,
    /// Created with the safer configuration after the full one was refused
    /// (`DEPLOYMENT_WARNING_RAISED`): check the impacted assets in the portal.
    pub partial: bool,
}

/// The Defender for Endpoint connector. One sign-in per tenant serves every
/// call of the run, as one `DefenderForEndpointService` does.
#[derive(Debug, Default)]
pub struct Defender {
    tokens: Mutex<BTreeMap<TenantLabel, Secret>>,
}

impl Defender {
    /// A connector with no tenant signed in yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The tenant's bearer token, signing in on first use.
    pub async fn token(&self, cx: TenantContext<'_>) -> Result<Secret, DefenderError> {
        if let Some(token) = self
            .tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&cx.tenant.label)
        {
            return Ok(token.clone());
        }
        let token = sign_in(cx).await?;
        self.tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(cx.tenant.label.clone(), token.clone());
        Ok(token)
    }

    /// A call to Graph with the session's headers.
    async fn graph(
        &self,
        cx: TenantContext<'_>,
        method: reqwest::Method,
        url: &str,
        body: Option<&Json>,
    ) -> Result<Answer, DefenderError> {
        let token = self.token(cx).await?;
        let mut builder = cx
            .http
            .request(method, url)
            .header("Authorization", format!("Bearer {}", token.expose()))
            .header("Content-Type", "application/json");
        if let Some(body) = body {
            builder = builder.body(json_body(cx, body)?);
        }
        Ok(crate::answer::exchange(cx, builder).await?)
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
                reqwest::Method::POST,
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
                reqwest::Method::POST,
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
    /// is followed, and an error answer is an error, never an empty listing.
    pub async fn list_rules(&self, cx: TenantContext<'_>) -> Result<Vec<Json>, DefenderError> {
        let mut rules = Vec::new();
        let mut next = Some(DETECTION_RULES_ENDPOINT.to_owned());
        while let Some(url) = next.take() {
            let answer = self.graph(cx, reqwest::Method::GET, &url, None).await?;
            if !(200..300).contains(&answer.status) {
                let reason = reqwest::StatusCode::from_u16(answer.status)
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
                next = Some(link.clone());
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
            .graph(cx, reqwest::Method::PATCH, &url, Some(body))
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
        let answer = self.graph(cx, reqwest::Method::DELETE, &url, None).await?;
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
                reqwest::Method::POST,
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
                    let name = truthy_or(column.get("name"), column.get("Name"));
                    let kind = truthy_or(column.get("type"), column.get("Type"));
                    Some(QueryColumn {
                        name: name.map_or_else(|| "None".to_owned(), python_str),
                        kind: kind.map(python_str),
                    })
                })
                .collect(),
            _ => Vec::new(),
        };
        let rows: Vec<Row> = match first_present(&body, "results", "Results") {
            Some(Json::Array(items)) => items
                .iter()
                .filter(|row| row.truthy())
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

/// Signs in with the tenant's client credentials (`_connect_to_tenant`).
async fn sign_in(cx: TenantContext<'_>) -> Result<Secret, DefenderError> {
    let tenant_id = cx.tenant.secret("tenant_id")?.expose().to_owned();
    let client_id = cx.tenant.secret("client_id")?.expose().to_owned();
    let client_secret = cx.tenant.secret("client_secret")?.expose().to_owned();
    let form = crate::encode::urlencode([
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("grant_type", "client_credentials"),
        ("scope", SCOPE),
    ]);
    let url = TOKEN_ENDPOINT.replace("{tenant_id}", &tenant_id);
    let builder = cx
        .http
        .request(reqwest::Method::POST, &url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form);
    let answer = crate::answer::exchange(cx, builder).await?;
    let tenant = &cx.tenant.label.tenant;
    if answer.status != 200 {
        return Err(DefenderError::Authentication {
            detail: format!(
                "Cannot authenticate against {tenant} (HTTP {})",
                answer.status
            ),
        });
    }
    match answer
        .json()
        .as_ref()
        .and_then(|body| body.get("access_token"))
    {
        Some(Json::Str(token)) if !token.is_empty() => Ok(Secret::new(token.clone())),
        _ => Err(DefenderError::Authentication {
            detail: format!("Microsoft Graph authentication for {tenant} returned no access token"),
        }),
    }
}

/// *body* as `requests`' `json=` writes it.
fn json_body(cx: TenantContext<'_>, body: &Json) -> Result<Vec<u8>, ConnectorError> {
    python_json(body).map_err(|error| ConnectorError::Setup {
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
        && template.get("impactedAssets").is_some_and(Json::truthy)
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
    answer.json().unwrap_or_else(|| {
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
    python_str(&error_body_value(answer))
}

/// `str(_error_message(response))`: Graph's `error.message`, or the body.
fn error_message(answer: &Answer) -> String {
    let body = error_body_value(answer);
    let message = body
        .get("error")
        .filter(|error| error.as_object().is_some())
        .and_then(|error| error.get("message"))
        .filter(|message| message.truthy());
    python_str(message.unwrap_or(&body))
}

/// `body.get(a, body.get(b, None))`.
fn first_present<'j>(body: &'j Json, first: &str, second: &str) -> Option<&'j Json> {
    body.get(first).or_else(|| body.get(second))
}

/// `a or b`.
fn truthy_or<'j>(first: Option<&'j Json>, second: Option<&'j Json>) -> Option<&'j Json> {
    first
        .filter(|value| value.truthy())
        .or(second)
        .filter(|value| value.truthy())
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

/// *query* with its comments and string literals blanked
/// (`strip_kql_literals_and_comments`).
pub fn strip_kql_literals_and_comments(query: &str) -> String {
    static PATTERNS: std::sync::OnceLock<Vec<regex::Regex>> = std::sync::OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        [
            r"(?s)/\*.*?\*/",
            r"//.*",
            r"@?'(?:''|[^'])*'",
            r#"@?"(?:""|[^"])*""#,
        ]
        .iter()
        .filter_map(|pattern| regex::Regex::new(pattern).ok())
        .collect()
    });
    let mut text = query.to_owned();
    for pattern in patterns {
        text = pattern.replace_all(&text, " ").into_owned();
    }
    text
}

fn is_word(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// The Defender XDR tables *query* names (`defender_xdr_tables_in_query`).
pub fn defender_xdr_tables_in_query(query: &str) -> Vec<String> {
    let query = strip_kql_literals_and_comments(query);
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
            let remote_id = match request.operation {
                Operation::Create => Some(
                    self.create_rule(cx, &body()?)
                        .await
                        .map_err(answer)?
                        .id
                        .to_string(),
                ),
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
