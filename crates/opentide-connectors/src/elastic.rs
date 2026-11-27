//! Elastic Security: Kibana's detection engine and Elasticsearch (UC-4.2,
//! #832): `platforms/elastic/client.py` (`ElasticClient`), `deployer.py`
//! (`ElasticDeploy._deploy_rule`), `es_checks.py` (the pre-flight and mapping
//! checks of RFC 0007 §6), `runner.py` (ES|QL, EQL and Lucene on
//! Elasticsearch; KQL through a rule preview, the one write, into the preview
//! index) and `validator.py` (each rule previewed as deploy would create it;
//! the RFC 0007 advisories), request for request.
//!
//! Every call carries the session's headers: `Accept` and `Content-Type`
//! `application/json`, `elastic-api-version: 2023-10-31` and, with a key,
//! `Authorization: ApiKey <api_key>`; Kibana's writes add `kbn-xsrf: true`.
//! The client retries as every connector does ([`RetryPolicy::standard`]):
//! a rule create, a search or a preview (`POST`) is never sent twice.
//!
//! The tenant's `index` (a list) is not a [`crate::Tenant`] setup value:
//! the calls that fall back on it take it as an argument.

use opentide_compile::deploy::PATH_SEGMENT;
use opentide_compile::json::{Json, Object};
use percent_encoding::utf8_percent_encode;

use crate::answer::Answer;
use crate::connector::{
    BoxFuture, LiveCheck, LiveValidator, Platform, Prober, QueryRunner, TenantContext,
    probe_verdict,
};
use crate::connector::{
    DeployError, DeployEvent, DeployFailure, DeployOutcome as ConnectorOutcome, DeployRequest,
    DeployWarning, Deployer, Operation,
};
use crate::connector::{
    QueryColumn, QueryOutcome, QueryRequest, Row, TimeWindow, columns_of, flatten, utc_z,
};
use crate::error::ConnectorError;
use crate::retry::RetryPolicy;
use crate::text::json_text;
use crate::{Credential, HttpSettings};

/// The platform's identifier.
pub const PLATFORM: &str = "elastic";

/// The Kibana API version every call names.
pub const API_VERSION: &str = "2023-10-31";

/// `ElasticClient`'s timeout when the caller names none, in seconds.
pub const DEFAULT_CLIENT_TIMEOUT: u64 = 30;

/// Kibana caps the alerts one rule execution writes.
pub const MAX_PREVIEW_ALERTS: usize = 1000;

/// Fields deploy keeps from the remote rule when the authored block leaves
/// them out (`PRESERVED_FIELDS`).
pub const PRESERVED_FIELDS: [&str; 11] = [
    "actions",
    "exceptions_list",
    "response_actions",
    "timeline_id",
    "timeline_title",
    "concurrent_searches",
    "items_per_search",
    "meta",
    "output_index",
    "namespace",
    "throttle",
];

/// What Kibana writes itself on a rule: the fields its lookup answers that
/// no deploy sends, and that a replace leaves to Kibana ([`holds`]).
const KIBANA_WRITES: [&str; 10] = [
    "id",
    "created_at",
    "created_by",
    "updated_at",
    "updated_by",
    "revision",
    "version",
    "immutable",
    "rule_source",
    "execution_summary",
];

/// The value Kibana gives `key` when a rule leaves it out, where it is not
/// empty ([`holds`]).
fn kibana_default(key: &str) -> Option<Json> {
    Some(match key {
        "max_signals" => Json::Int(100),
        "interval" => Json::Str("5m".into()),
        "from" => Json::Str("now-6m".into()),
        "to" => Json::Str("now".into()),
        _ => return None,
    })
}

/// Whether the tenant's rule, as its lookup answered it (`remote`), is
/// already what a replace with `compiled` would leave (#1711): every field
/// `compiled` sends has the same value on the tenant (`same`), and every
/// other field the tenant has is one Kibana writes itself
/// (`KIBANA_WRITES`), or holds what Kibana gives a field the rule leaves
/// out (empty, or `kibana_default`), so a replace would not change it.
/// A field opentide sent once and no longer sends keeps its value on the
/// tenant until a replace drops it: the rule is then not held, and is
/// replaced.
pub fn holds(remote: &Json, compiled: &Json) -> bool {
    let (Some(remote), Some(compiled)) = (remote.as_object(), compiled.as_object()) else {
        return false;
    };
    let sent = compiled.iter().all(|(key, value)| match remote.get(key) {
        Some(held) => same(value, held),
        None => is_empty(value),
    });
    sent && remote.iter().all(|(key, held)| {
        compiled.contains_key(key)
            || KIBANA_WRITES.contains(&key.as_str())
            || is_empty(held)
            || kibana_default(key).is_some_and(|default| same(&default, held))
    })
}

/// Whether the value a deploy sends (`sent`) is the one the tenant holds
/// (`held`): the same scalar (a number by its value, `5` and `5.0` alike),
/// the same items in the same order, and an object whose every member
/// sent is the same on the tenant, the tenant's other members empty (a
/// default Kibana adds, as a technique's `subtechnique: []`).
fn same(sent: &Json, held: &Json) -> bool {
    match (sent, held) {
        (Json::Object(sent), Json::Object(held)) => {
            sent.iter().all(|(key, value)| match held.get(key) {
                Some(held) => same(value, held),
                None => is_empty(value),
            }) && held
                .iter()
                .all(|(key, value)| sent.contains_key(key) || is_empty(value))
        }
        (Json::Array(sent), Json::Array(held)) => {
            sent.len() == held.len() && sent.iter().zip(held).all(|(sent, held)| same(sent, held))
        }
        (
            Json::Int(_) | Json::UInt(_) | Json::Float(_),
            Json::Int(_) | Json::UInt(_) | Json::Float(_),
        ) => number(sent) == number(held),
        _ => sent == held,
    }
}

/// A number's value, for [`same`].
#[expect(
    clippy::cast_precision_loss,
    reason = "Kibana's numbers (a risk score, a threshold) are small; equal values stay equal"
)]
fn number(value: &Json) -> Option<f64> {
    match value {
        Json::Int(number) => Some(*number as f64),
        Json::UInt(number) => Some(*number as f64),
        Json::Float(number) => Some(*number),
        _ => None,
    }
}

/// Whether a value is what Kibana answers for a field nobody set: `null`,
/// `false`, an empty string, list or object.
fn is_empty(value: &Json) -> bool {
    match value {
        Json::Null | Json::Bool(false) => true,
        Json::Str(text) => text.is_empty(),
        Json::Array(items) => items.is_empty(),
        Json::Object(members) => members.is_empty(),
        _ => false,
    }
}

/// The HTTP settings of an Elastic tenant: the connectors' retries and
/// *timeout* (whole seconds, at least one).
pub fn http_settings(timeout: std::time::Duration) -> HttpSettings {
    HttpSettings {
        timeout: std::time::Duration::from_secs(timeout.as_secs().max(1)),
        retry: RetryPolicy::standard(),
        ..HttpSettings::default()
    }
}

/// Why an Elasticsearch check, a preview or a deploy stopped.
#[derive(Debug, thiserror::Error)]
pub enum ElasticError {
    /// The rule itself failed (`ElasticRuleCheckError`): the other rules go on.
    #[error("{0}")]
    Rule(String),
    /// The tenant cannot check or take any rule (`ElasticTenantError`: auth,
    /// a missing preview privilege): the rest of its batch is not sent.
    #[error("{0}")]
    Tenant(String),
    /// The tenant could not be reached, or the run was cancelled.
    #[error(transparent)]
    Connector(#[from] ConnectorError),
}

/// What a rule's deploy should do (its status' strategy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    /// `PREVIEW` or `RELEASE`: the rule is created or updated, enabled.
    Active,
    /// `DISABLEMENT`: the rule is created or updated, disabled.
    Disablement,
    /// `DELETION`: the rule is deleted.
    Deletion,
}

/// One rule as deploy and the live check take it.
#[derive(Clone, Debug, PartialEq)]
pub struct ElasticRule {
    /// Its UUID, Kibana's `rule_id`.
    pub rule_id: String,
    /// Its name.
    pub name: String,
    /// Its strategy.
    pub strategy: Strategy,
    /// Its `elastic` block, as the model dumps it (`by_alias`, nulls kept).
    pub block: Json,
    /// The rule deploy creates (`compile_rule`), from `opentide-compile`.
    pub payload: Json,
}

/// What deploying one rule did (`_deploy_rule`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Deployed {
    /// It was not there and was created (`POST`).
    Created,
    /// It was there and was replaced (`PUT`), the remote's fields kept.
    Updated,
    /// It was there as the rule has it ([`holds`]): nothing was written
    /// (#1711).
    Unchanged,
    /// Its type changed: it was deleted and created again.
    Recreated,
    /// It was deleted (or was not there).
    Deleted,
    /// It failed; the rest of the batch goes on (`_deployment_error`).
    Failed {
        /// The log event (`create_elastic_rule_failed`).
        event: String,
        /// The answer's status, when there was one.
        status: Option<u16>,
        /// Why.
        error: String,
    },
}

/// A deployed rule and the Elasticsearch checks' warnings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeployOutcome {
    /// What happened.
    pub deployed: Deployed,
    /// The checks' warnings (`elasticsearch_check_warning`).
    pub warnings: Vec<String>,
}

/// The Elastic connector.
#[derive(Clone, Copy, Debug, Default)]
pub struct Elastic;

/// Why `find_rules` stopped (UC-4.4b).
#[derive(Debug, thiserror::Error)]
pub enum FindError {
    /// An error status: `Elastic answered HTTP <status> <reason> for <url>`.
    #[error("{0}")]
    Status(String),
    /// A body that is not JSON.
    #[error("{0}")]
    NotJson(String),
    /// The tenant could not be reached.
    #[error(transparent)]
    Connector(#[from] ConnectorError),
}

impl Elastic {
    /// One page of the space's rules (`ElasticClient.find_rules`):
    /// `GET <kibana>[/s/<space>]/api/detection_engine/rules/_find`.
    ///
    /// # Errors
    ///
    /// An error status, a body that is not JSON, or no answer.
    pub async fn find_rules(
        &self,
        cx: TenantContext<'_>,
        page: i64,
        per_page: i64,
    ) -> Result<Json, FindError> {
        let client = client(cx)?;
        let url = format!(
            "{}/api/detection_engine/rules/_find?{}",
            client.kibana_base,
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("page", page.to_string().as_str()),
                    ("per_page", per_page.to_string().as_str()),
                ])
                .finish()
        );
        let answer = client
            .call(cx, crate::transport::Method::GET, &url, None, false)
            .await?;
        // A 3xx is an error too: a redirect the client could not follow.
        if !(200..300).contains(&answer.status) {
            return Err(FindError::Status(http_error_text(&answer, &url)));
        }
        serde_json::from_slice(&answer.body)
            .map_err(|error| FindError::NotJson(format!("the response is not JSON: {error}")))
    }
}

/// The tenant's addresses and key (`ElasticClient.__init__`).
struct Client {
    kibana_base: String,
    elasticsearch: String,
    space: String,
    api_key: Option<String>,
}

fn client(cx: TenantContext<'_>) -> Result<Client, ConnectorError> {
    let text = |key: &str| -> Result<String, ConnectorError> {
        match cx.tenant.setup.get(key) {
            Some(Credential::Value(secret)) => Ok(secret.expose().to_owned()),
            Some(Credential::Placeholder { .. }) => cx.tenant.secret(key).map(|_| String::new()),
            None => Ok(String::new()),
        }
    };
    let kibana = text("url")?.trim_end_matches('/').to_owned();
    let elasticsearch = text("elasticsearch_url")?.trim_end_matches('/').to_owned();
    let space = Some(text("space")?)
        .filter(|space| !space.is_empty())
        .unwrap_or_else(|| "default".to_owned());
    let api_key = Some(text("api_key")?).filter(|key| !key.is_empty());
    let kibana_base = if space == "default" {
        kibana
    } else {
        format!("{kibana}/s/{space}")
    };
    Ok(Client {
        kibana_base,
        elasticsearch,
        space,
        api_key,
    })
}

impl Client {
    async fn call(
        &self,
        cx: TenantContext<'_>,
        method: crate::transport::Method,
        url: &str,
        body: Option<&Json>,
        xsrf: bool,
    ) -> Result<Answer, ConnectorError> {
        let mut builder = cx
            .http
            .request(method, url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("elastic-api-version", API_VERSION);
        if let Some(key) = &self.api_key {
            builder = builder.header("Authorization", format!("ApiKey {key}"));
        }
        if xsrf {
            builder = builder.header("kbn-xsrf", "true");
        } else {
            // Elasticsearch is only read: its checks (`POST /_query` among
            // them) write no rule (`HttpClient::writes_taken`).
            builder = builder.read_only();
        }
        if let Some(body) = body {
            builder =
                builder.body(
                    serde_json::to_vec(body).map_err(|error| ConnectorError::Setup {
                        platform: PLATFORM.into(),
                        tenant: cx.tenant.label.tenant.clone(),
                        message: format!("the request body cannot be written: {error}"),
                    })?,
                );
        }
        crate::answer::exchange(cx, builder).await
    }

    fn rules(&self) -> String {
        format!("{}/api/detection_engine/rules", self.kibana_base)
    }

    fn rule_query(&self, rule_id: &str) -> String {
        format!(
            "{}?{}",
            self.rules(),
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([("rule_id", rule_id)])
                .finish()
        )
    }

    /// `get_rule`.
    async fn get_rule(
        &self,
        cx: TenantContext<'_>,
        rule_id: &str,
    ) -> Result<Answer, ConnectorError> {
        self.call(
            cx,
            crate::transport::Method::GET,
            &self.rule_query(rule_id),
            None,
            false,
        )
        .await
    }

    /// `create_rule`.
    async fn create_rule(
        &self,
        cx: TenantContext<'_>,
        payload: &Json,
    ) -> Result<Answer, ConnectorError> {
        self.call(
            cx,
            crate::transport::Method::POST,
            &self.rules(),
            Some(payload),
            true,
        )
        .await
    }

    /// `update_rule`: `PUT`, with `rule_id` in the query when the payload has one.
    async fn update_rule(
        &self,
        cx: TenantContext<'_>,
        payload: &Json,
    ) -> Result<Answer, ConnectorError> {
        let url = match payload.get("rule_id").filter(|id| id.is_filled()) {
            Some(id) => self.rule_query(&json_text(id)),
            None => self.rules(),
        };
        self.call(cx, crate::transport::Method::PUT, &url, Some(payload), true)
            .await
    }

    /// `delete_rule`.
    async fn delete_rule(
        &self,
        cx: TenantContext<'_>,
        rule_id: &str,
    ) -> Result<Answer, ConnectorError> {
        self.call(
            cx,
            crate::transport::Method::DELETE,
            &self.rule_query(rule_id),
            None,
            true,
        )
        .await
    }

    /// `preview_rule`: the payload with `invocationCount` and `timeframeEnd`.
    async fn preview_rule(
        &self,
        cx: TenantContext<'_>,
        payload: &Json,
        invocation_count: i64,
        timeframe_end: &str,
    ) -> Result<Answer, ConnectorError> {
        let mut body = payload.as_object().cloned().unwrap_or_default();
        body.insert("invocationCount".into(), Json::Int(invocation_count));
        body.insert("timeframeEnd".into(), Json::Str(timeframe_end.to_owned()));
        let url = format!("{}/api/detection_engine/rules/preview", self.kibana_base);
        self.call(
            cx,
            crate::transport::Method::POST,
            &url,
            Some(&Json::Object(body)),
            true,
        )
        .await
    }

    /// `get_data_view_response`.
    async fn data_view(&self, cx: TenantContext<'_>, id: &str) -> Result<Answer, ConnectorError> {
        let url = format!("{}/api/data_views/data_view/{id}", self.kibana_base);
        self.call(cx, crate::transport::Method::GET, &url, None, false)
            .await
    }

    fn es(&self, endpoint: &str) -> String {
        format!("{}{endpoint}", self.elasticsearch)
    }

    /// `esql_query`.
    async fn esql_query(
        &self,
        cx: TenantContext<'_>,
        query: &str,
    ) -> Result<Answer, ConnectorError> {
        let mut body = Object::new();
        body.insert("query".into(), Json::Str(query.to_owned()));
        self.call(
            cx,
            crate::transport::Method::POST,
            &self.es("/_query"),
            Some(&Json::Object(body)),
            false,
        )
        .await
    }

    /// `resolve_index`.
    async fn resolve_index(
        &self,
        cx: TenantContext<'_>,
        pattern: &str,
    ) -> Result<Answer, ConnectorError> {
        let url = self.es(&format!(
            "/_resolve/index/{}?ignore_unavailable=true&allow_no_indices=true",
            utf8_percent_encode(pattern, PATH_SEGMENT)
        ));
        self.call(cx, crate::transport::Method::GET, &url, None, false)
            .await
    }

    /// `field_caps`.
    async fn field_caps(
        &self,
        cx: TenantContext<'_>,
        sources: &str,
        fields: &[String],
    ) -> Result<Answer, ConnectorError> {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("fields", &fields.join(","))
            .append_pair("ignore_unavailable", "true")
            .append_pair("allow_no_indices", "true")
            .finish();
        let url = self.es(&format!(
            "/{}/_field_caps?{query}",
            utf8_percent_encode(sources, PATH_SEGMENT),
        ));
        self.call(cx, crate::transport::Method::GET, &url, None, false)
            .await
    }
}

// ---- small readers of a block ----

/// `block.get(key, default)`: the default only when the key is missing.
fn get_or<'j>(block: &'j Json, key: &str, default: &'j Json) -> &'j Json {
    block.get(key).unwrap_or(default)
}

/// `block`'s object at `key`, when it is a non-empty object.
fn object_or_empty<'j>(block: &'j Json, key: &str) -> Option<&'j Object> {
    block
        .get(key)
        .filter(|value| value.is_filled())
        .and_then(Json::as_object)
}

/// The strings of a list value, each as text.
fn strings(value: Option<&Json>) -> Vec<String> {
    match value {
        Some(Json::Array(items)) => items.iter().map(json_text).collect(),
        _ => Vec::new(),
    }
}

/// The non-empty items, each once, in their first order.
fn distinct_non_empty(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if !item.is_empty() && !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn tenant_error(action: &str, status: u16) -> ElasticError {
    ElasticError::Tenant(format!("Elasticsearch {action} failed: HTTP {status}"))
}

/// `_error_payload`: the error's type, its reason and its text.
fn error_payload(answer: &Answer) -> (String, String, String) {
    let text = answer.text();
    let json_type = answer
        .content_type
        .as_deref()
        .is_some_and(|kind| kind.starts_with("application/json"));
    if !json_type {
        return (String::new(), text.clone(), text);
    }
    let Some(data) = answer.quotable_json() else {
        return (String::new(), text.clone(), text);
    };
    let empty = Json::Object(Object::new());
    let error = match &data {
        Json::Object(_) => get_or(&data, "error", &empty),
        _ => &empty,
    };
    if error.as_object().is_none() {
        return (String::new(), text.clone(), text);
    }
    let kind = error
        .get("type")
        .filter(|value| value.is_filled())
        .map(json_text)
        .unwrap_or_default();
    let reason = error
        .get("reason")
        .filter(|value| value.is_filled())
        .map_or_else(|| text.clone(), json_text);
    (kind, reason, error.to_compact())
}

/// The fields' capabilities, or the warning that the sources hold nothing.
enum Caps {
    Fields(Json),
    NotOnboarded,
}

async fn read_caps(
    client: &Client,
    cx: TenantContext<'_>,
    sources: &str,
    fields: &[String],
    failed: impl FnOnce(u16, String) -> String,
) -> Result<Caps, ElasticError> {
    let answer = client.field_caps(cx, sources, fields).await?;
    if matches!(answer.status, 401 | 403) {
        return Err(tenant_error("_field_caps", answer.status));
    }
    if answer.status != 200 {
        return Err(ElasticError::Rule(failed(answer.status, answer.text())));
    }
    let data = answer.json().unwrap_or(Json::Null);
    if matches!(data.get("indices"), Some(Json::Array(items)) if items.is_empty()) {
        return Ok(Caps::NotOnboarded);
    }
    Ok(Caps::Fields(
        data.get("fields")
            .cloned()
            .unwrap_or(Json::Object(Object::new())),
    ))
}

/// `any(isinstance(cap, dict) and cap.get(flag) is True for cap in caps.values())`.
fn any_cap(caps: &Json, flag: &str) -> bool {
    caps.as_object().is_some_and(|caps| {
        caps.values()
            .any(|cap| matches!(cap.get(flag), Some(Json::Bool(true))))
    })
}

impl Elastic {
    /// `resolve_rule_sources`: the index patterns of a rule, and whether it
    /// names them itself (a data view is looked up in Kibana).
    async fn resolve_rule_sources(
        client: &Client,
        cx: TenantContext<'_>,
        block: &Json,
        setup_index: &[String],
    ) -> Result<(Option<String>, bool), ElasticError> {
        let query_type = Json::Str("query".into());
        let rule_type = get_or(block, "type", &query_type);
        if rule_type.as_str() == Some("machine_learning") {
            return Ok((None, false));
        }
        if rule_type.as_str() == Some("esql") {
            let query = block
                .get("query")
                .filter(|q| q.is_filled())
                .map(json_text)
                .unwrap_or_default();
            let sources = esql_sources(&query);
            let explicit = !sources.is_empty();
            return Ok((explicit.then_some(sources), explicit));
        }
        if let Some(view) = block.get("data_view_id").filter(|id| id.is_filled()) {
            let view = json_text(view);
            let answer = client.data_view(cx, &view).await?;
            if matches!(answer.status, 401 | 403) {
                return Err(ElasticError::Tenant(format!(
                    "Kibana data_view '{view}' lookup failed: HTTP {}",
                    answer.status
                )));
            }
            if answer.status != 200 {
                return Err(ElasticError::Rule(format!(
                    "Data view '{view}' lookup failed (HTTP {})",
                    answer.status
                )));
            }
            let data = answer.json().unwrap_or(Json::Null);
            let title = data_view_title(&data);
            return Ok((title, true));
        }
        if block.get("index").is_some_and(Json::is_filled) {
            return Ok((Some(strings(block.get("index")).join(",")), true));
        }
        if !setup_index.is_empty() {
            return Ok((Some(setup_index.join(",")), true));
        }
        Ok((None, false))
    }

    /// `run_esql_preflight`: the query with `| LIMIT 0`; its columns.
    async fn esql_preflight(
        client: &Client,
        cx: TenantContext<'_>,
        query: &str,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<Json>, ElasticError> {
        let preflight = format!("{}\n| LIMIT 0", query.trim_end());
        let answer = client.esql_query(cx, &preflight).await?;
        if matches!(answer.status, 401 | 403) {
            return Err(tenant_error("_query", answer.status));
        }
        if answer.status == 200 {
            return Ok(
                match answer.json().as_ref().and_then(|data| data.get("columns")) {
                    Some(Json::Array(columns)) => columns.clone(),
                    _ => Vec::new(),
                },
            );
        }
        let (kind, reason, blob) = error_payload(&answer);
        if kind == "parsing_exception" || blob.contains("parsing_exception") {
            return Err(ElasticError::Rule(format!(
                "ES|QL parsing exception: {reason}"
            )));
        }
        if kind == "verification_exception" || blob.contains("verification_exception") {
            let sources = esql_sources(query);
            if !sources.is_empty() {
                let resolved = client.resolve_index(cx, &sources).await?;
                if matches!(resolved.status, 401 | 403) {
                    return Err(tenant_error("_resolve/index", resolved.status));
                }
                if resolved.status == 200 {
                    let data = resolved.json().unwrap_or(Json::Null);
                    let empty = |key: &str| !data.get(key).is_some_and(Json::is_filled);
                    if empty("indices") && empty("aliases") && empty("data_streams") {
                        warnings.push(format!("ES|QL sources not onboarded yet: {sources}"));
                        return Ok(Vec::new());
                    }
                }
            }
            return Err(ElasticError::Rule(format!(
                "ES|QL verification exception: {reason}"
            )));
        }
        Err(ElasticError::Rule(format!(
            "ES|QL pre-flight failed (HTTP {}): {reason}",
            answer.status
        )))
    }

    /// `run_elasticsearch_checks`: the pre-flight and mapping checks of a
    /// rule block; returns the warnings, fails on the rule or the tenant.
    pub async fn checks(
        &self,
        cx: TenantContext<'_>,
        block: &Json,
        setup_index: &[String],
    ) -> Result<Vec<String>, ElasticError> {
        let client = client(cx)?;
        let mut warnings = Vec::new();
        let query_type = Json::Str("query".into());
        let rule_type = get_or(block, "type", &query_type).clone();
        let mut esql_columns: Option<Vec<Json>> = None;
        if rule_type.as_str() == Some("esql") && block.get("query").is_some_and(Json::is_filled) {
            let query = block.get("query").map(json_text).unwrap_or_default();
            esql_columns = Some(Self::esql_preflight(&client, cx, &query, &mut warnings).await?);
        }
        let resolved = Self::resolve_rule_sources(&client, cx, block, setup_index).await?;
        Self::aggregation_fields(
            &client,
            cx,
            block,
            esql_columns.as_deref(),
            &mut warnings,
            &resolved,
        )
        .await?;
        Self::timestamp_fields(&client, cx, block, &mut warnings, &resolved).await?;
        Self::threat_match_fields(&client, cx, block, &mut warnings, &resolved).await?;
        Ok(warnings)
    }

    /// `run_aggregation_fields_check`.
    async fn aggregation_fields(
        client: &Client,
        cx: TenantContext<'_>,
        block: &Json,
        esql_columns: Option<&[Json]>,
        warnings: &mut Vec<String>,
        resolved: &(Option<String>, bool),
    ) -> Result<(), ElasticError> {
        let mut fields: Vec<String> = Vec::new();
        let suppression = object_or_empty(block, "suppression");
        let group_by = suppression
            .and_then(|s| s.get("group_by"))
            .filter(|g| g.is_filled());
        fields.extend(strings(group_by));
        if let Some(threshold) = object_or_empty(block, "threshold") {
            match threshold.get("field").filter(|f| f.is_filled()) {
                Some(Json::Array(items)) => fields.extend(items.iter().map(json_text)),
                Some(other) => fields.push(json_text(other)),
                None => {}
            }
            if let Some(cardinality) = threshold.get("cardinality").and_then(Json::as_object)
                && let Some(field) = cardinality.get("field").filter(|f| f.is_filled())
            {
                fields.push(json_text(field));
            }
        }
        if let Some(new_terms) = object_or_empty(block, "new_terms") {
            fields.extend(strings(new_terms.get("fields").filter(|f| f.is_filled())));
        }
        let fields = distinct_non_empty(fields);
        if fields.is_empty() {
            return Ok(());
        }
        if block.get("type").and_then(Json::as_str) == Some("esql") {
            let group_by = strings(group_by);
            if let (false, Some(columns)) = (group_by.is_empty(), esql_columns) {
                let mut names: Vec<String> = columns
                    .iter()
                    .filter_map(|column| column.get("name").map(json_text))
                    .collect();
                if names.is_empty() {
                    return Ok(());
                }
                names.sort();
                names.dedup();
                for field in &group_by {
                    if !names.contains(field) {
                        return Err(ElasticError::Rule(format!(
                            "ES|QL suppression group_by field '{field}' not in query columns: {}",
                            names.join(", ")
                        )));
                    }
                }
            }
            return Ok(());
        }
        let (sources, explicit) = resolved;
        if !explicit {
            warnings.push(
                "aggregation field check skipped: rule has no explicit index, data_view_id, or tenant index"
                    .into(),
            );
            return Ok(());
        }
        let Some(sources) = sources.as_deref().filter(|s| !s.is_empty()) else {
            return Ok(());
        };
        let caps = read_caps(client, cx, sources, &fields, |status, text| {
            format!("Aggregation field check failed (HTTP {status}): {text}")
        })
        .await?;
        let Caps::Fields(caps) = caps else {
            warnings.push(format!("aggregation sources not onboarded yet: {sources}"));
            return Ok(());
        };
        for field in &fields {
            let Some(type_caps) = caps.get(field) else {
                return Err(ElasticError::Rule(format!(
                    "Field '{field}' not found in mappings for sources: {sources}"
                )));
            };
            if !any_cap(type_caps, "aggregatable") {
                return Err(ElasticError::Rule(format!(
                    "Field '{field}' is not aggregatable in sources: {sources}"
                )));
            }
        }
        Ok(())
    }

    /// `run_timestamp_fields_check`.
    async fn timestamp_fields(
        client: &Client,
        cx: TenantContext<'_>,
        block: &Json,
        warnings: &mut Vec<String>,
        resolved: &(Option<String>, bool),
    ) -> Result<(), ElasticError> {
        let overrides = object_or_empty(block, "overrides").and_then(|o| o.get("timestamp"));
        let eql = object_or_empty(block, "eql").and_then(|e| e.get("timestamp_field"));
        let fields = distinct_non_empty(
            [overrides, eql]
                .into_iter()
                .flatten()
                .filter(|field| field.is_filled())
                .map(json_text)
                .filter(|field| field != "@timestamp")
                .collect(),
        );
        if fields.is_empty() {
            return Ok(());
        }
        let Some(sources) = resolved.0.as_deref().filter(|s| !s.is_empty()) else {
            return Ok(());
        };
        let caps = read_caps(client, cx, sources, &fields, |status, text| {
            format!("Timestamp field check failed (HTTP {status}): {text}")
        })
        .await?;
        let Caps::Fields(caps) = caps else {
            warnings.push(format!("timestamp sources not onboarded yet: {sources}"));
            return Ok(());
        };
        for field in &fields {
            let Some(type_caps) = caps.get(field) else {
                warnings.push(format!(
                    "Timestamp field '{field}' not found in mappings yet for sources: {sources}"
                ));
                continue;
            };
            let dates = ["date", "date_nanos"];
            let is_date = type_caps.as_object().is_some_and(|caps| {
                caps.iter().any(|(kind, cap)| {
                    dates.contains(&kind.as_str())
                        || cap
                            .get("type")
                            .and_then(Json::as_str)
                            .is_some_and(|kind| dates.contains(&kind))
                })
            });
            if !is_date {
                let found = match type_caps.as_object() {
                    Some(caps) if !caps.is_empty() => {
                        let mut kinds: Vec<&str> = caps.keys().map(String::as_str).collect();
                        kinds.sort_unstable();
                        kinds.join(", ")
                    }
                    _ => "unknown".to_owned(),
                };
                return Err(ElasticError::Rule(format!(
                    "Timestamp field '{field}' is not a date/date_nanos field (found: {found}) in sources: {sources}"
                )));
            }
        }
        Ok(())
    }

    /// `_check_searchable_fields`.
    async fn searchable_fields(
        client: &Client,
        cx: TenantContext<'_>,
        sources: &str,
        fields: &[String],
        label: &str,
        warnings: &mut Vec<String>,
    ) -> Result<(), ElasticError> {
        let caps = read_caps(client, cx, sources, fields, |status, text| {
            format!("{label} field check failed (HTTP {status}): {text}")
        })
        .await?;
        let Caps::Fields(caps) = caps else {
            warnings.push(format!("{label} sources not onboarded yet: {sources}"));
            return Ok(());
        };
        for field in fields {
            let Some(type_caps) = caps.get(field) else {
                warnings.push(format!(
                    "{label} field '{field}' not found in mappings yet for sources: {sources}"
                ));
                continue;
            };
            if !any_cap(type_caps, "searchable") {
                return Err(ElasticError::Rule(format!(
                    "{label} field '{field}' is not searchable in sources: {sources}"
                )));
            }
        }
        Ok(())
    }

    /// `run_threat_match_fields_check`.
    async fn threat_match_fields(
        client: &Client,
        cx: TenantContext<'_>,
        block: &Json,
        warnings: &mut Vec<String>,
        resolved: &(Option<String>, bool),
    ) -> Result<(), ElasticError> {
        if block.get("type").and_then(Json::as_str) != Some("threat_match") {
            return Ok(());
        }
        let Some(threat) = block.get("threat").and_then(Json::as_object) else {
            return Ok(());
        };
        let mut event_fields = Vec::new();
        let mut indicator_fields = Vec::new();
        if let Some(Json::Array(groups)) = threat.get("mapping") {
            for group in groups {
                if let Some(Json::Array(entries)) = group.get("entries") {
                    for entry in entries.iter().filter(|e| e.as_object().is_some()) {
                        if let Some(field) = entry.get("field").filter(|f| f.is_filled()) {
                            event_fields.push(json_text(field));
                        }
                        if let Some(value) = entry.get("value").filter(|v| v.is_filled()) {
                            indicator_fields.push(json_text(value));
                        }
                    }
                }
            }
        }
        let event_fields = distinct_non_empty(event_fields);
        let indicator_fields = distinct_non_empty(indicator_fields);
        let threat_sources = match threat.get("index") {
            Some(Json::Array(items)) => items
                .iter()
                .filter(|item| item.is_filled())
                .map(json_text)
                .collect::<Vec<_>>()
                .join(","),
            _ => String::new(),
        };
        if !threat_sources.is_empty() && !indicator_fields.is_empty() {
            Self::searchable_fields(
                client,
                cx,
                &threat_sources,
                &indicator_fields,
                "Threat indicator",
                warnings,
            )
            .await?;
        }
        if !event_fields.is_empty()
            && let Some(sources) = resolved.0.as_deref().filter(|s| !s.is_empty())
        {
            Self::searchable_fields(
                client,
                cx,
                sources,
                &event_fields,
                "Threat match event",
                warnings,
            )
            .await?;
        }
        Ok(())
    }

    /// Deploys one rule (`ElasticDeploy._deploy_rule`): deletes it, or runs
    /// its Elasticsearch checks, then creates it, replaces it (keeping the
    /// remote's fields the block leaves out) or, when its type changes,
    /// deletes and creates it. A prebuilt rule is never modified. A 401 or
    /// 403 fails the tenant ([`ElasticError::Tenant`]), and so does a
    /// connection that failed ([`ConnectorError::Unreachable`]: refused, DNS,
    /// TLS, a proxy, or dropped mid-request) on any step, and a gateway's 502,
    /// 503 or 504 in front of Kibana on the lookup or a delete
    /// ([`ConnectorError::Gateway`]): the other rules would only wait on the
    /// same failure. Any other refusal fails the rule ([`Deployed::Failed`]).
    pub async fn deploy_rule(
        &self,
        cx: TenantContext<'_>,
        rule: &ElasticRule,
        setup_index: &[String],
    ) -> Result<DeployOutcome, ElasticError> {
        let client = client(cx)?;
        let rule_id = rule.rule_id.as_str();
        let failed = |event: &str, status: Option<u16>, error: String| DeployOutcome {
            deployed: Deployed::Failed {
                event: event.to_owned(),
                status,
                error,
            },
            warnings: Vec::new(),
        };
        if rule.strategy == Strategy::Deletion {
            let answer = match client.delete_rule(cx, rule_id).await {
                Ok(answer) => answer,
                Err(error @ (ConnectorError::Cancelled | ConnectorError::Unreachable { .. })) => {
                    return Err(error.into());
                }
                Err(error) => {
                    return Ok(failed(
                        "delete_elastic_rule_failed",
                        None,
                        error.to_string(),
                    ));
                }
            };
            return match answer.status {
                200 | 404 => Ok(DeployOutcome {
                    deployed: Deployed::Deleted,
                    warnings: Vec::new(),
                }),
                401 | 403 => Err(ElasticError::Tenant(http_error_text(
                    &answer,
                    &client.rule_query(rule_id),
                ))),
                status @ 502..=504 => Err(gateway(cx, &answer, status, "a delete")),
                status if !(200..300).contains(&status) => Ok(failed(
                    "delete_elastic_rule_failed",
                    None,
                    http_error_text(&answer, &client.rule_query(rule_id)),
                )),
                _ => Ok(DeployOutcome {
                    deployed: Deployed::Deleted,
                    warnings: Vec::new(),
                }),
            };
        }
        let warnings = match self.checks(cx, &rule.block, setup_index).await {
            Ok(warnings) => warnings,
            Err(ElasticError::Rule(error)) => {
                return Ok(failed("elasticsearch_checks_failed", None, error));
            }
            Err(other) => return Err(other),
        };
        self.write_rule(cx, &client, rule, warnings).await
    }

    /// Creates, replaces or recreates `rule` after its checks raised
    /// `warnings` (`_deploy_rule` past the checks).
    async fn write_rule(
        &self,
        cx: TenantContext<'_>,
        client: &Client,
        rule: &ElasticRule,
        warnings: Vec<String>,
    ) -> Result<DeployOutcome, ElasticError> {
        let tenant = cx.tenant.label.tenant.clone();
        let rule_id = rule.rule_id.as_str();
        let with = |deployed: Deployed| DeployOutcome {
            deployed,
            warnings: warnings.clone(),
        };
        let mut compiled = rule.payload.as_object().cloned().unwrap_or_default();
        compiled.insert(
            "enabled".into(),
            Json::Bool(rule.strategy != Strategy::Disablement),
        );
        let get = match client.get_rule(cx, rule_id).await {
            Ok(answer) => answer,
            Err(error @ (ConnectorError::Cancelled | ConnectorError::Unreachable { .. })) => {
                return Err(error.into());
            }
            Err(error) => {
                return Ok(with(Deployed::Failed {
                    event: "get_elastic_rule_failed".into(),
                    status: None,
                    error: error.to_string(),
                }));
            }
        };
        tenant_refused_lookup(cx, &get)?;
        if get.status == 404 {
            let answer = match client.create_rule(cx, &Json::Object(compiled)).await {
                Ok(answer) => answer,
                Err(error @ (ConnectorError::Cancelled | ConnectorError::Unreachable { .. })) => {
                    return Err(error.into());
                }
                Err(error) => {
                    return Ok(with(Deployed::Failed {
                        event: "create_elastic_rule_failed".into(),
                        status: None,
                        error: error.to_string(),
                    }));
                }
            };
            return Ok(with(
                write_failed(&answer, "create_elastic_rule_failed", &tenant)?
                    .unwrap_or(Deployed::Created),
            ));
        }
        if get.status != 200 {
            return Ok(with(Deployed::Failed {
                event: "get_elastic_rule_failed".into(),
                status: Some(get.status),
                error: kibana_error(&get),
            }));
        }
        let remote = get.json().ok_or_else(|| {
            ElasticError::Connector(ConnectorError::Answer {
                platform: PLATFORM.into(),
                tenant: tenant.clone(),
                address: client.kibana_base.clone(),
                reason: "Kibana answered the rule lookup with a body that is not JSON".into(),
            })
        })?;
        if is_prebuilt_rule(&remote) {
            return Ok(with(Deployed::Failed {
                event: "refusing_to_modify_prebuilt_rule".into(),
                status: None,
                error: "refusing to modify prebuilt rule".into(),
            }));
        }
        for key in PRESERVED_FIELDS {
            if !compiled.contains_key(key)
                && let Some(value) = remote.get(key)
            {
                compiled.insert(key.into(), value.clone());
            }
        }
        let compiled = Json::Object(compiled);
        // The tenant holds the rule as a replace would write it: nothing to
        // send (#1711).
        if holds(&remote, &compiled) {
            return Ok(with(Deployed::Unchanged));
        }
        if remote.get("type") != compiled.get("type") {
            let deleted = client.delete_rule(cx, rule_id).await?;
            if deleted.status != 404
                && let Some(failed) =
                    write_failed(&deleted, "recreate_elastic_rule_delete_failed", &tenant)?
            {
                return Ok(with(failed));
            }
            let created = client.create_rule(cx, &compiled).await?;
            return Ok(with(
                write_failed(&created, "recreate_elastic_rule_failed", &tenant)?
                    .unwrap_or(Deployed::Recreated),
            ));
        }
        let updated = client.update_rule(cx, &compiled).await?;
        Ok(with(
            write_failed(&updated, "update_elastic_rule_failed", &tenant)?
                .unwrap_or(Deployed::Updated),
        ))
    }

    /// Kibana's preview of the rule *payload*, once, ending at *end*
    /// (`ElasticQueryRunner.preview_rule`). Creates no rule.
    pub async fn preview_rule(
        &self,
        cx: TenantContext<'_>,
        payload: &Json,
        end: jiff::Timestamp,
    ) -> Result<Json, ConnectorError> {
        let client = client(cx)?;
        let tenant = &cx.tenant.label.tenant;
        let answer = client.preview_rule(cx, payload, 1, &utc_ms(end)).await?;
        match answer.status {
            400 => {
                return Err(ConnectorError::refused(
                    PLATFORM,
                    tenant,
                    format!("Rule schema error on preview: {}", answer.text()),
                    None,
                ));
            }
            401 | 403 => {
                return Err(ConnectorError::authentication(
                    PLATFORM,
                    tenant,
                    format!(
                        "Tenant authentication/authorization failed: HTTP {}",
                        answer.status
                    ),
                ));
            }
            200 => {}
            status => {
                let detail = answer.not_json_detail().unwrap_or_else(|| answer.text());
                return Err(ConnectorError::refused(
                    PLATFORM,
                    tenant,
                    format!("Preview failed (HTTP {status}): {detail}"),
                    None,
                ));
            }
        }
        match answer.json() {
            Some(body @ Json::Object(_)) => Ok(body),
            Some(_) => Ok(Json::Object(Object::new())),
            None => Err(ConnectorError::refused(
                PLATFORM,
                tenant,
                format!("Kibana answered the preview on {tenant} with a body that is not JSON"),
                answer.not_json_detail(),
            )),
        }
    }

    /// `validate query --live`'s check of one rule (`ElasticValidator.
    /// _validate_rule`, after the advisories): its Elasticsearch checks, then
    /// a preview of the rule deploy would create, ending at *now*. Returns
    /// the warnings.
    pub async fn validate_rule(
        &self,
        cx: TenantContext<'_>,
        rule: &ElasticRule,
        setup_index: &[String],
        now: jiff::Timestamp,
    ) -> Result<Vec<String>, ElasticError> {
        let mut warnings = self.checks(cx, &rule.block, setup_index).await?;
        let preview = match self.preview_rule(cx, &rule.payload, now).await {
            Ok(preview) => preview,
            Err(ConnectorError::Authentication { message, .. }) => {
                return Err(ElasticError::Tenant(message));
            }
            Err(
                refused @ (ConnectorError::Refused { .. } | ConnectorError::QueryTimedOut { .. }),
            ) => return Err(ElasticError::Rule(refused.text())),
            Err(error) => return Err(error.into()),
        };
        if matches!(preview.get("isAborted"), Some(Json::Bool(true))) {
            warnings.push("Kibana aborted the preview before it finished".into());
        }
        let mut errors: Vec<String> = Vec::new();
        if let Some(Json::Array(logs)) = preview.get("logs") {
            for entry in logs.iter().filter(|entry| entry.as_object().is_some()) {
                if let Some(Json::Array(items)) = entry.get("warnings") {
                    warnings.extend(items.iter().map(json_text));
                }
                if let Some(Json::Array(items)) = entry.get("errors") {
                    for error in items.iter().map(json_text) {
                        if error.contains("preview-index") || error.contains("preview.alerts") {
                            return Err(ElasticError::Tenant(format!(
                                "Tenant configuration error: missing preview-index privilege ({error})"
                            )));
                        }
                        errors.push(error);
                    }
                }
            }
        }
        if !errors.is_empty() {
            return Err(ElasticError::Rule(format!(
                "Preview validation failed for rule '{}': {}",
                rule.name,
                errors.join("; ")
            )));
        }
        Ok(warnings)
    }

    /// Runs a query (`ElasticQueryRunner.run`): ES|QL, EQL and Lucene on
    /// Elasticsearch; KQL (`kuery`) as a rule preview, whose alerts are the
    /// rows. *setup_index* is the tenant's `index`.
    pub async fn run(
        &self,
        cx: TenantContext<'_>,
        request: &QueryRequest,
        setup_index: &[String],
    ) -> Result<QueryOutcome, ConnectorError> {
        let client = client(cx)?;
        let tenant = cx.tenant.label.tenant.as_str();
        let language = if request.language.is_empty() {
            "esql"
        } else {
            request.language.as_str()
        };
        if language == "esql" {
            return esql(&client, cx, request, tenant).await;
        }
        if language == "kuery" && request.data_view.is_some() && request.index.is_empty() {
            return kuery_preview(&client, cx, request, "", tenant).await;
        }
        let indices = indices(&client, cx, request, tenant, setup_index).await?;
        match language {
            "eql" => eql(&client, cx, request, &indices, tenant).await,
            "lucene" => lucene(&client, cx, request, &indices, tenant).await,
            _ => kuery_preview(&client, cx, request, &indices, tenant).await,
        }
    }

    /// `validate query --live`'s check of one query: [`Elastic::run`] for one row.
    pub async fn check(
        &self,
        cx: TenantContext<'_>,
        request: &QueryRequest,
        setup_index: &[String],
    ) -> Result<QueryOutcome, ConnectorError> {
        self.run(cx, &request.for_check(), setup_index).await
    }
}

impl QueryRunner for Elastic {
    /// ES|QL, EQL, Lucene or KQL (a rule preview) over the request's
    /// window; the tenant's `index` is read when the request names none.
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        Box::pin(async move { Elastic::run(self, cx, request, cx.tenant.list("index")).await })
    }
}

impl LiveValidator for Elastic {
    /// The runner's check of one query: one row over the request's window.
    /// (`validate query --live` checks a rule as a whole with
    /// [`Elastic::validate_rule`]: its Elasticsearch checks and a preview.)
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        Box::pin(async move {
            let result = self.check(cx, request, cx.tenant.list("index")).await?;
            Ok(LiveCheck {
                result: Some(result),
                errors: Vec::new(),
                warnings: Vec::new(),
            })
        })
    }
}

/// The events a rule's failed deploy is logged with (`_deployment_error`),
/// each its [`DeployFailure`]'s code.
pub const FAILURE_EVENTS: [&str; 8] = [
    "elasticsearch_checks_failed",
    "refusing_to_modify_prebuilt_rule",
    "delete_elastic_rule_failed",
    "get_elastic_rule_failed",
    "create_elastic_rule_failed",
    "recreate_elastic_rule_delete_failed",
    "recreate_elastic_rule_failed",
    "update_elastic_rule_failed",
];

/// The warning a deploy without the rule's block raises: the Elasticsearch
/// checks, which read the block, did not run.
pub const CHECKS_SKIPPED: &str = "elastic_checks_skipped";

/// The warning each Elasticsearch check raises (`elasticsearch_check_warning`).
pub const CHECK_WARNING: &str = "elasticsearch_check_warning";

/// A deploy request's body: the Kibana rule (`payload`) and the rule's
/// `elastic` block (`block`), as `deploy_plan` and `opentide deploy` write
/// it; or the Kibana rule alone, with no block. The rule's `rule_id` must be
/// `rule_id`, the one the deploy looks the rule up by.
fn deploy_body(body: &[u8], rule_id: &str) -> Result<(Json, Option<Json>), String> {
    let body: Json = serde_json::from_slice(body)
        .map_err(|error| format!("the compiled body is not JSON: {error}"))?;
    let (payload, block) = match (body.get("payload"), body.get("block")) {
        (Some(payload @ Json::Object(_)), None) => (payload.clone(), None),
        (Some(payload @ Json::Object(_)), Some(block @ Json::Object(_))) => {
            (payload.clone(), Some(block.clone()))
        }
        (Some(Json::Object(_)), Some(_)) => {
            return Err("the body's block is not an elastic block".to_owned());
        }
        (Some(_), _) => return Err("the body's payload is not a Kibana rule".to_owned()),
        (None, Some(_)) => return Err("the body has a block but no payload".to_owned()),
        (None, None) if body.as_object().is_some() => (body, None),
        (None, None) => return Err("the compiled body is not a Kibana rule".to_owned()),
    };
    match payload.get("rule_id").and_then(Json::as_str) {
        Some(id) if id == rule_id => Ok((payload, block)),
        Some(id) => Err(format!(
            "the Kibana rule's rule_id is {id:?}, not the request's {rule_id:?}"
        )),
        None => Err(format!(
            "the Kibana rule has no rule_id; the request's is {rule_id:?}"
        )),
    }
}

impl Prober for Elastic {
    /// Opens the tenant as a deploy does (its addresses, space and key
    /// resolved), then reads one page of one rule from Kibana: `GET
    /// .../api/detection_engine/rules/_find?page=1&per_page=1`, which writes
    /// nothing and needs the API key.
    fn probe<'a>(&'a self, cx: TenantContext<'a>) -> BoxFuture<'a, Result<(), DeployError>> {
        crate::connector::probing(async move {
            let client = client(cx)?;
            let url = format!(
                "{}/api/detection_engine/rules/_find?page=1&per_page=1",
                client.kibana_base
            );
            let answer = client
                .call(cx, crate::transport::Method::GET, &url, None, false)
                .await?;
            probe_verdict(
                PLATFORM,
                &cx.tenant.label.tenant,
                "reading the detection rules",
                answer.status,
            )
        })
    }
}

impl Deployer for Elastic {
    /// The tenant's addresses, space and key: nothing is sent.
    fn open<'a>(
        &'a self,
        cx: TenantContext<'a>,
    ) -> BoxFuture<'a, Result<(), crate::connector::DeployError>> {
        crate::connector::opening(async move { client(cx).map(|_| ()) })
    }

    /// One rule, Kibana's `rule_id` the request's: deleted, or checked
    /// against Elasticsearch, then created when Kibana has no such rule,
    /// replaced (keeping the remote's fields the rule leaves out) or, when
    /// its type changes, deleted and created again. [`Operation::Create`]
    /// and [`Operation::Update`] do the same; a [`Operation::Disable`]
    /// writes the rule disabled. The body is `{"payload": <Kibana rule>,
    /// "block": <elastic block>}`, as `deploy_plan` holds it and `opentide
    /// deploy` sends it, the rule's
    /// `rule_id` the request's (else the rule fails, nothing sent); a bare
    /// Kibana rule
    /// deploys without the checks, which read the block, and says so with
    /// the unraised warning [`CHECKS_SKIPPED`]. The checks' findings are
    /// [`CHECK_WARNING`]s; what was done is the outcome's event
    /// (`elastic_rule_created`, `_updated`, `_recreated`, `_deleted`, with
    /// its `rule_id`). The tenant's `index` is the checks' fallback source.
    ///
    /// A rule Kibana or the checks refuse fails with its event's code
    /// ([`FAILURE_EVENTS`]) and the answer's status, the checks' warnings in
    /// [`DeployError::partial`] (and, when a rule whose type changed was
    /// deleted but not created again, its `elastic_rule_deleted` event). A
    /// key Kibana or Elasticsearch refuses (401, 403) fails the tenant
    /// (`tenant_refused`), and so does a connection that failed (refused,
    /// DNS, TLS, a proxy, or dropped mid-request) on any step, a gateway's
    /// 502, 503 or 504 on the lookup or a delete (`tenant_gateway`), and any
    /// connector error during the checks, a replace or a type change (a read
    /// timeout included); a read timeout or an answer that cannot be read on
    /// the lookup, a create or a delete fails the rule with that step's code,
    /// as `opentide deploy` reports it.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<ConnectorOutcome, DeployError>> {
        Box::pin(async move {
            let tenant = cx.tenant.label.tenant.as_str();
            let located = |failure: DeployFailure| {
                failure
                    .with_field("platform", PLATFORM)
                    .with_field("tenant", tenant)
            };
            let (payload, block) = if request.operation == Operation::Delete {
                (Json::Null, None)
            } else {
                deploy_body(&request.body, &request.rule_id).map_err(|message| {
                    DeployError::from(ConnectorError::refused(PLATFORM, tenant, message, None))
                })?
            };
            let rule = ElasticRule {
                rule_id: request.rule_id.clone(),
                name: payload
                    .get("name")
                    .and_then(Json::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                strategy: match request.operation {
                    Operation::Delete => Strategy::Deletion,
                    Operation::Disable => Strategy::Disablement,
                    Operation::Create | Operation::Update => Strategy::Active,
                },
                block: block.clone().unwrap_or(Json::Null),
                payload,
            };
            let deployed = match &block {
                Some(_) => self.deploy_rule(cx, &rule, cx.tenant.list("index")).await,
                None if rule.strategy == Strategy::Deletion => {
                    self.deploy_rule(cx, &rule, &[]).await
                }
                None => match client(cx) {
                    Ok(client) => self.write_rule(cx, &client, &rule, Vec::new()).await,
                    Err(error) => Err(error.into()),
                },
            };
            let outcome = deployed.map_err(|error| elastic_tenant_failure(error, tenant))?;
            let mut warnings: Vec<DeployWarning> = Vec::new();
            if block.is_none() && rule.strategy != Strategy::Deletion {
                warnings.push(
                    DeployWarning::new(
                        CHECKS_SKIPPED,
                        "the body carries no elastic block, so the Elasticsearch checks did \
                         not run",
                    )
                    .unraised(),
                );
            }
            warnings.extend(
                outcome
                    .warnings
                    .into_iter()
                    .map(|warning| DeployWarning::new(CHECK_WARNING, warning)),
            );
            let event = match &outcome.deployed {
                Deployed::Created => "elastic_rule_created",
                Deployed::Updated => "elastic_rule_updated",
                Deployed::Unchanged => crate::connector::RULE_UNCHANGED,
                Deployed::Recreated => "elastic_rule_recreated",
                Deployed::Deleted => "elastic_rule_deleted",
                Deployed::Failed {
                    event,
                    status,
                    error,
                } => {
                    let code = FAILURE_EVENTS
                        .into_iter()
                        .find(|known| known == event)
                        .unwrap_or("tenant_refused");
                    let mut failure = located(DeployFailure::new(code, error.clone()));
                    if let Some(status) = status {
                        failure = failure.with_status(*status);
                    }
                    let mut partial =
                        ConnectorOutcome::new(None, request.operation).with_warnings(warnings);
                    if code == "recreate_elastic_rule_failed" {
                        // Deleted for its type change, not created again.
                        partial.events = vec![
                            DeployEvent::new("elastic_rule_deleted")
                                .with_field("rule_id", request.rule_id.as_str()),
                        ];
                    }
                    return Err(DeployError::rule(failure).with_partial(partial));
                }
            };
            let mut done = ConnectorOutcome::new(
                (outcome.deployed != Deployed::Deleted).then(|| request.rule_id.clone()),
                request.operation,
            )
            .with_warnings(warnings);
            done.events =
                vec![DeployEvent::new(event).with_field("rule_id", request.rule_id.as_str())];
            Ok(done)
        })
    }
}

/// A deploy's failure that is not a rule's answer: the tenant's. A refused
/// key or privilege ([`ElasticError::Tenant`]) keeps no connector error,
/// every connection failure keeps its own; [`ElasticError::Rule`], which
/// the checks' own failure never is (that is `elasticsearch_checks_failed`),
/// is the rule's `tenant_refused`.
fn elastic_tenant_failure(error: ElasticError, tenant: &str) -> DeployError {
    match error {
        ElasticError::Rule(message) => DeployError::rule(
            DeployFailure::new("tenant_refused", message)
                .with_field("platform", PLATFORM)
                .with_field("tenant", tenant),
        ),
        ElasticError::Tenant(message) => DeployError::tenant(
            DeployFailure::new("tenant_refused", message)
                .with_field("platform", PLATFORM)
                .with_field("tenant", tenant),
        ),
        ElasticError::Connector(error) => {
            let mut failed = DeployError::from(error);
            failed.scope = crate::connector::DeployScope::Tenant;
            failed
        }
    }
}

impl Platform for Elastic {
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

/// An error status of *answer* to *url*.
fn http_error_text(answer: &Answer, url: &str) -> String {
    let reason = crate::transport::StatusCode::from_u16(answer.status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .map(|reason| format!(" {reason}"))
        .unwrap_or_default();
    format!("Elastic answered HTTP {}{reason} for {url}", answer.status)
}

/// `_write_failed`: a 401 or 403 fails the tenant; any other error fails
/// the rule.
fn write_failed(
    answer: &Answer,
    event: &str,
    tenant: &str,
) -> Result<Option<Deployed>, ElasticError> {
    if matches!(answer.status, 401 | 403) {
        return Err(ElasticError::Tenant(format!(
            "Tenant {tenant} auth error: HTTP {}: {}",
            answer.status,
            kibana_error(answer)
        )));
    }
    // A 3xx is a failure: a redirect the client could not follow is no
    // rule written (#1142).
    if !(200..300).contains(&answer.status) {
        return Ok(Some(Deployed::Failed {
            event: event.to_owned(),
            status: Some(answer.status),
            error: kibana_error(answer),
        }));
    }
    Ok(None)
}

/// `_kibana_error`: Kibana's `message`, else the body's text.
fn kibana_error(answer: &Answer) -> String {
    match answer.quotable_json() {
        Some(body) => match body.get("message").filter(|m| m.is_filled()) {
            Some(message) if body.as_object().is_some() => json_text(message),
            _ => answer.text(),
        },
        None => answer.text(),
    }
}

/// The rule lookup's answer when it fails the tenant: a 401 or 403 (the
/// key), or a gateway's 502, 503 or 504.
fn tenant_refused_lookup(cx: TenantContext<'_>, get: &Answer) -> Result<(), ElasticError> {
    match get.status {
        status @ (401 | 403) => Err(ElasticError::Tenant(format!(
            "Tenant {} auth error: HTTP {status}",
            cx.tenant.label.tenant
        ))),
        status @ 502..=504 => Err(gateway(cx, get, status, "the rule lookup")),
        _ => Ok(()),
    }
}

/// A gateway's 502, 503 or 504 in front of Kibana (a proxy, or Elastic
/// Cloud's front end with Kibana down), already retried by the client: the
/// tenant's failure, not the rule's.
fn gateway(cx: TenantContext<'_>, answer: &Answer, status: u16, step: &str) -> ElasticError {
    let tenant = &cx.tenant.label.tenant;
    let detail = answer
        .not_json_detail()
        .unwrap_or_else(|| kibana_error(answer));
    ElasticError::Connector(ConnectorError::Gateway {
        platform: PLATFORM.into(),
        tenant: tenant.clone(),
        message: format!(
            "Kibana of elastic tenant '{tenant}' answered {step} with HTTP {status}: {detail}"
        ),
        status,
    })
}

/// `_is_prebuilt_rule`.
fn is_prebuilt_rule(remote: &Json) -> bool {
    if matches!(remote.get("immutable"), Some(Json::Bool(true))) {
        return true;
    }
    remote
        .get("rule_source")
        .and_then(|source| source.get("type"))
        .and_then(Json::as_str)
        == Some("external")
}

/// A data view's title: `(body.get("data_view") or body).get("title")`.
fn data_view_title(body: &Json) -> Option<String> {
    let view = body
        .get("data_view")
        .filter(|view| view.is_filled())
        .unwrap_or(body);
    view.get("title").filter(|t| t.is_filled()).map(json_text)
}

/// `format_utc_ms`: UTC to the second, `.000Z`.
pub fn utc_ms(moment: jiff::Timestamp) -> String {
    let civil = jiff::tz::Offset::UTC.to_datetime(moment);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        civil.year(),
        civil.month(),
        civil.day(),
        civil.hour(),
        civil.minute(),
        civil.second()
    )
}

/// `_range`: the window on `@timestamp`.
fn range(window: &TimeWindow) -> Json {
    let mut bounds = Object::new();
    bounds.insert("gte".into(), Json::Str(utc_z(window.start)));
    bounds.insert("lte".into(), Json::Str(utc_z(window.end)));
    bounds.insert("format".into(), "strict_date_optional_time".into());
    let mut field = Object::new();
    field.insert("@timestamp".into(), Json::Object(bounds));
    let mut range = Object::new();
    range.insert("range".into(), Json::Object(field));
    Json::Object(range)
}

/// `{"@timestamp": {"order": "desc", "unmapped_type": "date"}}`, in a list.
fn newest_first() -> Json {
    let mut order = Object::new();
    order.insert("order".into(), "desc".into());
    order.insert("unmapped_type".into(), "date".into());
    let mut sort = Object::new();
    sort.insert("@timestamp".into(), Json::Object(order));
    Json::Array(vec![Json::Object(sort)])
}

fn object(pairs: Vec<(&str, Json)>) -> Json {
    Json::Object(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn int(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

/// `esql_with_limit`: `| LIMIT limit+1` appended unless the query has one.
pub fn esql_with_limit(query: &str, limit: usize) -> String {
    static LIMIT: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    let text = query.trim();
    let has_limit = LIMIT
        .get_or_init(|| regex::Regex::new(r"(?i)\|\s*limit\s+\d+").ok())
        .as_ref()
        .is_some_and(|limit| limit.is_match(&mask_query(text, false)));
    if has_limit {
        return text.to_owned();
    }
    format!("{text}\n| LIMIT {}", limit.saturating_add(1))
}

/// `_body`: the answer's JSON object, or the refusal it is.
fn body(answer: &Answer, tenant: &str, what: &str) -> Result<Json, ConnectorError> {
    let Some(body) = answer.json() else {
        return Err(ConnectorError::refused(
            PLATFORM,
            tenant,
            format!("Elastic did not answer the {what} query on {tenant} with JSON"),
            answer.not_json_detail(),
        ));
    };
    if answer.status != 200 {
        let body = answer.quotable_json().unwrap_or(body);
        let mut reason: Option<String> = None;
        if body.as_object().is_some() {
            match body.get("error") {
                Some(error @ Json::Object(_)) => {
                    let root = match error.get("root_cause").filter(|r| r.is_filled()) {
                        Some(Json::Array(items)) => items.first().cloned(),
                        Some(other) => Some(other.clone()),
                        None => None,
                    };
                    reason = root
                        .as_ref()
                        .filter(|root| root.as_object().is_some())
                        .and_then(|root| root.get("reason"))
                        .filter(|r| r.is_filled())
                        .map(json_text);
                    if reason.is_none() {
                        reason = error.get("reason").filter(|r| r.is_filled()).map(json_text);
                    }
                }
                Some(error) if error.is_filled() => reason = Some(json_text(error)),
                _ => {}
            }
            if reason.is_none() {
                reason = body.get("message").filter(|m| m.is_filled()).map(json_text);
            }
        }
        let detail = reason.unwrap_or_else(|| answer.text().chars().take(500).collect());
        return Err(ConnectorError::refused(
            PLATFORM,
            tenant,
            format!(
                "Elastic refused the {what} query on {tenant} (HTTP {})",
                answer.status
            ),
            (!detail.is_empty()).then_some(detail),
        ));
    }
    Ok(match body {
        Json::Object(_) => body,
        _ => Json::Object(Object::new()),
    })
}

fn hits(body: &Json) -> Json {
    match body.get("hits") {
        Some(hits @ Json::Object(_)) => hits.clone(),
        _ => Json::Object(Object::new()),
    }
}

/// Whether `answer` is Elasticsearch's 404 for `index`, an index that does not
/// exist (`index_not_found_exception`, at the error or in its root cause). When
/// the error names the index (`index`, or `resource.id`), it must be `index`: a
/// missing index the request did not name is a refusal. A 404 for any other
/// reason, and every other status, is not.
fn is_index_not_found(answer: &Answer, index: &str) -> bool {
    if answer.status != 404 {
        return false;
    }
    let Some(body) = answer.json() else {
        return false;
    };
    let Some(error) = body.get("error") else {
        return false;
    };
    let is_missing = |value: &Json| {
        let missing = matches!(
            value.get("type"),
            Some(Json::Str(kind)) if kind == "index_not_found_exception"
        );
        let names = |key: &str| match value.get(key) {
            Some(Json::Str(name)) => Some(name.clone()),
            _ => None,
        };
        missing
            && names("index")
                .into_iter()
                .chain(names("resource.id"))
                .all(|name| name == index)
    };
    is_missing(error) || list(error.get("root_cause")).iter().any(is_missing)
}

/// `_total`: `hits.total` (or its `value`) when it is an integer.
fn total(hits: &Json) -> i64 {
    let total = hits.get("total");
    let total = match total {
        Some(Json::Object(_)) => total.and_then(|t| t.get("value")),
        other => other,
    };
    match total {
        Some(Json::Int(value)) => *value,
        _ => 0,
    }
}

fn exceeds(total: i64, limit: usize) -> bool {
    usize::try_from(total).is_ok_and(|total| total > limit)
}

/// `_event_row`: the hit's `_source` flattened, after `_sequence` and `_index`.
fn event_row(hit: &Json) -> Json {
    let mut row = match hit.get("_source") {
        Some(Json::Object(source)) => flatten(source),
        _ => Object::new(),
    };
    if let Some(index) = hit.get("_index").filter(|index| !index.is_null()) {
        let mut front = Object::new();
        front.insert("_index".into(), index.clone());
        front.extend(row);
        row = front;
    }
    if let Some(sequence) = hit.get("_sequence") {
        let mut front = Object::new();
        front.insert("_sequence".into(), sequence.clone());
        front.extend(row);
        row = front;
    }
    Json::Object(row)
}

fn list(value: Option<&Json>) -> Vec<Json> {
    match value {
        Some(Json::Array(items)) => items.clone(),
        _ => Vec::new(),
    }
}

/// The first *limit* rows, each an object.
fn objects(rows: &[Json], limit: usize) -> Vec<Row> {
    rows.iter()
        .take(limit)
        .filter_map(Json::as_object)
        .cloned()
        .collect()
}

async fn esql(
    client: &Client,
    cx: TenantContext<'_>,
    request: &QueryRequest,
    tenant: &str,
) -> Result<QueryOutcome, ConnectorError> {
    let sent = esql_with_limit(&request.text, request.limit);
    let payload = object(vec![
        ("query", Json::Str(sent.clone())),
        ("filter", range(&request.window)),
    ]);
    let answer = client
        .call(
            cx,
            crate::transport::Method::POST,
            &client.es("/_query"),
            Some(&payload),
            false,
        )
        .await?;
    let body = body(&answer, tenant, "ES|QL")?;
    let columns: Vec<QueryColumn> = list(body.get("columns"))
        .iter()
        .filter(|column| column.as_object().is_some())
        .map(|column| QueryColumn {
            name: column.get("name").map_or_else(|| "null".into(), json_text),
            kind: column.get("type").filter(|t| !t.is_null()).map(json_text),
        })
        .collect();
    let rows: Vec<Json> = list(body.get("values"))
        .into_iter()
        .filter_map(|values| match values {
            Json::Array(values) => Some(Json::Object(
                columns
                    .iter()
                    .map(|column| column.name.clone())
                    .zip(values)
                    .collect(),
            )),
            _ => None,
        })
        .collect();
    let truncated = rows.len() > request.limit;
    Ok(QueryOutcome {
        columns,
        rows: objects(&rows, request.limit),
        truncated,
        partial: body.get("is_partial").is_some_and(Json::is_true),
        warnings: Vec::new(),
        vendor_query_id: None,
        sent: (sent != request.text.trim()).then_some(sent),
        language: Some("esql".into()),
    })
}

async fn eql(
    client: &Client,
    cx: TenantContext<'_>,
    request: &QueryRequest,
    indices: &str,
    tenant: &str,
) -> Result<QueryOutcome, ConnectorError> {
    let payload = object(vec![
        ("query", Json::Str(request.text.clone())),
        ("size", int(request.limit.saturating_add(1))),
        ("filter", range(&request.window)),
    ]);
    let url = client.es(&format!(
        "/{}/_eql/search",
        utf8_percent_encode(indices, PATH_SEGMENT)
    ));
    let answer = client
        .call(
            cx,
            crate::transport::Method::POST,
            &url,
            Some(&payload),
            false,
        )
        .await?;
    let body = body(&answer, tenant, "EQL")?;
    let hits = hits(&body);
    let mut events = list(hits.get("events"));
    for (number, sequence) in list(hits.get("sequences")).iter().enumerate() {
        for event in list(sequence.get("events")) {
            if let Json::Object(mut event) = event {
                event.insert("_sequence".into(), int(number + 1));
                events.push(Json::Object(event));
            } else {
                events.push(event);
            }
        }
    }
    let rows: Vec<Json> = events
        .iter()
        .filter(|event| event.as_object().is_some())
        .map(event_row)
        .collect();
    let kept = objects(&rows, request.limit);
    Ok(QueryOutcome {
        columns: columns_of(&kept),
        truncated: rows.len() > request.limit || exceeds(total(&hits), request.limit),
        rows: kept,
        partial: body.get("timed_out").is_some_and(Json::is_true),
        warnings: Vec::new(),
        vendor_query_id: None,
        sent: None,
        language: Some("eql".into()),
    })
}

async fn lucene(
    client: &Client,
    cx: TenantContext<'_>,
    request: &QueryRequest,
    indices: &str,
    tenant: &str,
) -> Result<QueryOutcome, ConnectorError> {
    let query_string = object(vec![(
        "query_string",
        object(vec![("query", Json::Str(request.text.clone()))]),
    )]);
    let payload = object(vec![
        ("size", int(request.limit.saturating_add(1))),
        (
            "query",
            object(vec![(
                "bool",
                object(vec![
                    ("must", Json::Array(vec![query_string])),
                    ("filter", Json::Array(vec![range(&request.window)])),
                ]),
            )]),
        ),
        ("sort", newest_first()),
    ]);
    let url = client.es(&format!(
        "/{}/_search",
        utf8_percent_encode(indices, PATH_SEGMENT)
    ));
    let answer = client
        .call(
            cx,
            crate::transport::Method::POST,
            &url,
            Some(&payload),
            false,
        )
        .await?;
    let body = body(&answer, tenant, "Lucene")?;
    let hits = hits(&body);
    let rows: Vec<Json> = list(hits.get("hits"))
        .iter()
        .filter(|hit| hit.as_object().is_some())
        .map(event_row)
        .collect();
    let kept = objects(&rows, request.limit);
    Ok(QueryOutcome {
        columns: columns_of(&kept),
        truncated: rows.len() > request.limit || exceeds(total(&hits), request.limit),
        rows: kept,
        partial: body.get("timed_out").is_some_and(Json::is_true),
        warnings: Vec::new(),
        vendor_query_id: None,
        sent: None,
        language: Some("lucene".into()),
    })
}

#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
async fn kuery_preview(
    client: &Client,
    cx: TenantContext<'_>,
    request: &QueryRequest,
    indices: &str,
    tenant: &str,
) -> Result<QueryOutcome, ConnectorError> {
    let alerts = (request.limit.saturating_add(1)).min(MAX_PREVIEW_ALERTS);
    let seconds = request.window.seconds();
    let mut payload = Object::new();
    payload.insert("type".into(), "query".into());
    payload.insert("language".into(), "kuery".into());
    payload.insert("query".into(), Json::Str(request.text.clone()));
    payload.insert("name".into(), "opentide query preview".into());
    payload.insert(
        "description".into(),
        "Read-only preview run by opentide query".into(),
    );
    payload.insert("risk_score".into(), Json::Int(21));
    payload.insert("severity".into(), "low".into());
    payload.insert("interval".into(), Json::Str(format!("{seconds}s")));
    payload.insert("from".into(), Json::Str(format!("now-{seconds}s")));
    payload.insert("max_signals".into(), int(alerts));
    match (&request.data_view, request.index.is_empty()) {
        (Some(view), true) => {
            payload.insert("data_view_id".into(), Json::Str(view.clone()));
        }
        _ => {
            payload.insert(
                "index".into(),
                Json::Array(
                    indices
                        .split(',')
                        .map(|i| Json::Str(i.to_owned()))
                        .collect(),
                ),
            );
        }
    }
    let answer = client
        .preview_rule(cx, &Json::Object(payload), 1, &utc_z(request.window.end))
        .await?;
    let preview = body(&answer, tenant, "KQL preview")?;
    let errors: Vec<String> = list(preview.get("logs"))
        .iter()
        .filter(|entry| entry.as_object().is_some())
        .flat_map(|entry| list(entry.get("errors")))
        .map(|error| json_text(&error))
        .collect();
    if !errors.is_empty() {
        return Err(ConnectorError::refused(
            PLATFORM,
            tenant,
            format!("Kibana refused the KQL query on {tenant}"),
            Some(errors.join("; ")),
        ));
    }
    let preview_id = preview
        .get("previewId")
        .filter(|id| id.is_filled())
        .map(json_text)
        .unwrap_or_default();
    if preview_id.is_empty() {
        return Err(ConnectorError::refused(
            PLATFORM,
            tenant,
            format!("Kibana returned no preview id on {tenant}"),
            None,
        ));
    }
    let search = object(vec![
        ("size", int(alerts)),
        (
            "query",
            object(vec![(
                "term",
                object(vec![(
                    "kibana.alert.rule.uuid",
                    Json::Str(preview_id.clone()),
                )]),
            )]),
        ),
        ("sort", newest_first()),
    ]);
    let url = client.es(&format!(
        "/.preview.alerts-security.alerts-{}/_search",
        utf8_percent_encode(&client.space, PATH_SEGMENT)
    ));
    let found = client
        .call(
            cx,
            crate::transport::Method::POST,
            &url,
            Some(&search),
            false,
        )
        .await?;
    // The preview alerts index is created by the first alert a preview raises:
    // a preview that raised none, on a Kibana that never raised one, has no
    // index to read, which is no alerts. Any other refusal stays an error.
    // Kibana writes the alerts to its own cluster, so an `elasticsearch_url`
    // that points at another cluster never holds the index: it reads as 0 rows
    // too.
    let alerts_index = format!(".preview.alerts-security.alerts-{}", client.space);
    let body = if is_index_not_found(&found, &alerts_index) {
        Json::Object(Object::new())
    } else {
        body(&found, tenant, "preview alerts")?
    };
    let rows: Vec<Json> = list(hits(&body).get("hits"))
        .iter()
        .filter(|hit| hit.as_object().is_some())
        .map(|hit| match event_row(hit) {
            Json::Object(row) => Json::Object(
                row.into_iter()
                    .filter(|(key, _)| !key.starts_with("kibana.") && !key.starts_with("signal."))
                    .collect(),
            ),
            other => other,
        })
        .collect();
    let mut warnings = vec![
        "KQL runs only inside Kibana rules: the rows are the alerts a rule preview raised"
            .to_owned(),
    ];
    if request.limit.saturating_add(1) > MAX_PREVIEW_ALERTS {
        warnings.push(format!(
            "a preview raises at most {MAX_PREVIEW_ALERTS} alerts"
        ));
    }
    let aborted = preview.get("isAborted").is_some_and(Json::is_true);
    if aborted {
        warnings.push("Kibana aborted the preview before it finished".into());
    }
    let kept = objects(&rows, request.limit);
    Ok(QueryOutcome {
        columns: columns_of(&kept),
        truncated: rows.len() > request.limit || (rows.len() >= alerts && alerts <= request.limit),
        rows: kept,
        partial: aborted,
        warnings,
        vendor_query_id: Some(preview_id),
        sent: None,
        language: Some("kuery".into()),
    })
}

/// `_indices`: `--index`, the data view's title, or the tenant's index.
async fn indices(
    client: &Client,
    cx: TenantContext<'_>,
    request: &QueryRequest,
    tenant: &str,
    setup_index: &[String],
) -> Result<String, ConnectorError> {
    if !request.index.is_empty() {
        return Ok(request.index.join(","));
    }
    if let Some(view) = &request.data_view {
        let answer = client.data_view(cx, view).await?;
        if answer.status != 200 {
            return Err(ConnectorError::refused(
                PLATFORM,
                tenant,
                format!(
                    "cannot read data view {view:?} on {tenant} (HTTP {})",
                    answer.status
                ),
                answer.not_json_detail(),
            ));
        }
        let Some(body) = answer.json() else {
            return Err(ConnectorError::refused(
                PLATFORM,
                tenant,
                format!("cannot read data view {view:?} on {tenant}"),
                answer.not_json_detail(),
            ));
        };
        if let Some(title) = data_view_title(&body) {
            return Ok(title);
        }
    }
    if !setup_index.is_empty() {
        return Ok(setup_index.join(","));
    }
    Err(ConnectorError::refused(
        PLATFORM,
        tenant,
        format!("no index to search on {tenant}"),
        Some("pass --index, or set index in the tenant's [tenants.setup]".into()),
    ))
}

// ---- query text (`platforms/elastic/query_text.py`) ----

/// `mask_query`: comments, and the contents of string literals and
/// backquoted identifiers, blanked; newlines kept. Each blanked character
/// becomes as many spaces as its UTF-8 bytes, so a byte offset in the mask is
/// the same byte offset in the text.
pub fn mask_query(text: &str, keep_strings: bool) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let blank = |out: &mut Vec<u8>, start: usize, end: usize| {
        for byte in &mut out[start..end] {
            if *byte != b'\r' && *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    let length = bytes.len();
    let mut i = 0;
    while i < length {
        if bytes[i..].starts_with(b"//") {
            let end = bytes[i..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(length, |offset| i + offset);
            blank(&mut out, i, end);
            i = end;
        } else if bytes[i..].starts_with(b"/*") {
            let mut depth = 1;
            let mut j = i + 2;
            while j < length && depth > 0 {
                if bytes[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if bytes[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            let end = j.min(length);
            blank(&mut out, i, end);
            i = end;
        } else if bytes[i..].starts_with(b"\"\"\"") {
            let close = text[i + 3..].find("\"\"\"").map(|offset| i + 3 + offset);
            let content_end = close.unwrap_or(length);
            let mut end = length.min(content_end + 3);
            while end < length && end < content_end + 5 && bytes[end] == b'"' {
                end += 1;
            }
            if !keep_strings {
                blank(&mut out, i + 3, content_end);
            }
            i = end;
        } else if bytes[i] == b'"' || bytes[i] == b'`' {
            let quote = bytes[i];
            let mut j = i + 1;
            let mut closing = (length, length);
            while j < length {
                let byte = bytes[j];
                if quote == b'"' && byte == b'\\' {
                    j += 2;
                } else if byte == quote {
                    if quote == b'`' && bytes[j..].starts_with(b"``") {
                        j += 2;
                        continue;
                    }
                    closing = (j, j + 1);
                    break;
                } else {
                    j += 1;
                }
            }
            if !keep_strings {
                blank(&mut out, i + 1, closing.0.min(length));
            }
            i = closing.1;
        } else {
            i += 1;
        }
    }
    // Every byte replaced is a whole character's (ASCII delimiters bound
    // each blanked run), so the mask is UTF-8.
    String::from_utf8_lossy(&out).into_owned()
}

fn edge(character: Option<char>) -> bool {
    character.is_some_and(|c| c.is_alphanumeric() || "_.*:-".contains(c))
}

/// Where `METADATA` starts as a keyword (`_METADATA`), any case.
fn metadata_at(masked: &str) -> Option<usize> {
    let lowered = masked.to_ascii_lowercase();
    let mut from = 0;
    while let Some(offset) = lowered[from..].find("metadata") {
        let at = from + offset;
        let before = masked[..at].chars().next_back();
        let after = masked[at + 8..].chars().next();
        if !edge(before) && !edge(after) {
            return Some(at);
        }
        from = at + 8;
    }
    None
}

/// `esql_sources`: the index sources of the `FROM` or `TS` command, comma-joined.
pub fn esql_sources(query: &str) -> String {
    static SET: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    static SOURCE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    let set = SET.get_or_init(|| regex::Regex::new(r"(?i)^\s*SET\b[^;|]*;").ok());
    let source = SOURCE.get_or_init(|| regex::Regex::new(r"(?i)^\s*(?:FROM|TS)\b").ok());
    let (Some(set), Some(source)) = (set, source) else {
        return String::new();
    };
    let masked = mask_query(query, false);
    let plain = mask_query(query, true);
    let mut start = 0;
    while let Some(statement) = set.find(&masked[start..]) {
        if statement.end() == 0 {
            break;
        }
        start += statement.end();
    }
    let Some(command) = source.find(&masked[start..]) else {
        return String::new();
    };
    let begin = start + command.end();
    let (masked_bytes, plain_bytes) = (masked.as_bytes(), plain.as_bytes());
    let mut top_masked: Vec<u8> = Vec::new();
    let mut top_plain: Vec<u8> = Vec::new();
    let mut depth = 0usize;
    for (index, &byte) in masked_bytes.iter().enumerate().skip(begin) {
        match byte {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            byte if depth == 0 => {
                if byte == b'|' {
                    break;
                }
                top_masked.push(byte);
                top_plain.push(plain_bytes.get(index).copied().unwrap_or(b' '));
            }
            _ => {}
        }
    }
    let mut head = String::from_utf8_lossy(&top_plain).into_owned();
    if let Some(at) = metadata_at(&String::from_utf8_lossy(&top_masked))
        && head.is_char_boundary(at)
    {
        head.truncate(at);
    }
    head.split(',')
        .map(|raw| {
            raw.trim()
                .trim_matches(|c| c == '"' || c == '\'' || c == '`')
        })
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

/// `esql_aggregates`: a pipeline step is `STATS`.
pub fn esql_aggregates(query: &str) -> bool {
    static STATS: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    let Some(stats) = STATS
        .get_or_init(|| regex::Regex::new(r"(?i)^\s*STATS\b").ok())
        .as_ref()
    else {
        return false;
    };
    mask_query(query, false)
        .split('|')
        .any(|step| stats.is_match(step))
}

/// `esql_has_metadata_id`: `METADATA … _id` outside comments and strings.
pub fn esql_has_metadata_id(query: &str) -> bool {
    static ID: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    let Some(id) = ID
        .get_or_init(|| regex::Regex::new(r"\b_id\b").ok())
        .as_ref()
    else {
        return false;
    };
    let masked = mask_query(query, false);
    let lowered = masked.to_ascii_lowercase();
    let mut from = 0;
    while let Some(offset) = lowered[from..].find("metadata") {
        let at = from + offset;
        let before = masked[..at].chars().next_back();
        let after = masked[at + 8..].chars().next();
        if !edge(before) && !edge(after) {
            let rest = &masked[at + 8..];
            let segment = rest.split('|').next().unwrap_or_default();
            if id.is_match(segment) {
                return true;
            }
        }
        from = at + 8;
    }
    false
}

/// `eql_is_sequence`.
pub fn eql_is_sequence(query: &str) -> bool {
    static SEQUENCE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    SEQUENCE
        .get_or_init(|| regex::Regex::new(r"(?i)^\s*sequence\b").ok())
        .as_ref()
        .is_some_and(|sequence| sequence.is_match(&mask_query(query, false)))
}

/// `eql_maxspan`: the sequence's `maxspan=` as written and in milliseconds.
pub fn eql_maxspan(query: &str) -> Option<(String, u128)> {
    static MAXSPAN: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    let maxspan = MAXSPAN
        .get_or_init(|| regex::Regex::new(r"(?i)\bmaxspan\s*=\s*((\d+)\s*(ms|s|m|h|d))\b").ok())
        .as_ref()?;
    let masked = mask_query(query, false);
    let found = maxspan.captures(&masked)?;
    let amount: u128 = found.get(2)?.as_str().parse().ok()?;
    let unit = match found.get(3)?.as_str().to_ascii_lowercase().as_str() {
        "ms" => 1,
        "s" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        _ => 86_400_000,
    };
    Some((found.get(1)?.as_str().to_owned(), amount * unit))
}

// ---- advisories (`validator._emit_rule_advisories`) ----

/// Kibana severity bands of the explicit risk score (RFC 0007 §3).
const RISK_BANDS: [(&str, i64, i64); 4] = [
    ("low", 0, 21),
    ("medium", 22, 47),
    ("high", 48, 73),
    ("critical", 74, 100),
];

/// The Kibana severity band of an explicit risk score (RFC 0007 §3), as
/// `(low, high)`; `None` for a severity outside the four.
pub fn risk_band(severity: &str) -> Option<(i64, i64)> {
    RISK_BANDS
        .iter()
        .find(|(name, _, _)| *name == severity)
        .map(|(_, low, high)| (*low, *high))
}

/// The log event an advisory code replaced, which its log line carries as
/// `legacy_event` (`advisories.LEGACY_EVENTS`); empty for an unknown code.
pub fn legacy_event(code: &str) -> &'static str {
    match code {
        "lookback_zero" => "elastic_lookback_zero_warning",
        "lookback_long" | "threshold_lookback" => "elastic_lookback_long_warning",
        "esql_metadata_id" => "elastic_esql_metadata_id_warning",
        "eql_maxspan_window" | "eql_maxspan_lookback" => "elastic_eql_maxspan_window_warning",
        "risk_band" => "elastic_risk_score_band_warning",
        "technique_not_enterprise" => "skipping_non_enterprise_technique",
        _ => "",
    }
}

/// The advisories a live check reports about an Elastic rule, as the codes
/// `opentide validate` and the language server name them
/// (`_emit_rule_advisories`). *severity* is the compiled rule's Kibana
/// `severity`; *suppression* the tenant's `setup.suppression`;
/// *non_enterprise* whether the rule names a technique outside ATT&CK
/// Enterprise. An unreadable duration is an error, never a skipped advisory.
pub fn advisories(
    block: &Json,
    severity: &str,
    suppression: bool,
    non_enterprise: bool,
) -> Result<Vec<String>, String> {
    use opentide_compile::duration::elastic_seconds;
    let mut warnings = Vec::new();
    let scheduling = block.get("scheduling").filter(|s| s.is_filled());
    let text = |key: &str, default: &str| {
        scheduling
            .and_then(|s| s.get(key))
            .filter(|value| !value.is_null())
            .map_or_else(|| default.to_owned(), json_text)
    };
    let interval = text("interval", "5m");
    let lookback = text("lookback", "1m");
    let interval_secs = elastic_seconds(&interval, false)?;
    let lookback_secs = elastic_seconds(&lookback, true)?;
    let rule_type = block.get("type").and_then(Json::as_str).unwrap_or_default();
    if scheduling.is_some() && lookback_secs == 0 {
        warnings.push(opentide_core::codes::LOOKBACK_ZERO.to_owned());
    }
    if lookback_secs > 3600 {
        warnings.push(opentide_core::codes::LOOKBACK_LONG.to_owned());
    }
    if rule_type == "threshold" && lookback_secs > interval_secs {
        warnings.push(opentide_core::codes::THRESHOLD_LOOKBACK.to_owned());
    }
    let query = block.get("query").filter(|q| q.is_filled()).map(json_text);
    if rule_type == "esql"
        && let Some(query) = &query
        && !esql_aggregates(query)
        && !esql_has_metadata_id(query)
    {
        warnings.push(opentide_core::codes::ESQL_METADATA_ID.to_owned());
    }
    let score = match block.get("risk") {
        Some(Json::Int(score)) => Some(*score),
        Some(risk @ Json::Object(_)) => match risk.get("score") {
            Some(Json::Int(score)) => Some(*score),
            _ => None,
        },
        _ => None,
    };
    if let Some(score) = score
        && let Some((_, low, high)) = RISK_BANDS.iter().find(|(name, _, _)| *name == severity)
        && !(*low..=*high).contains(&score)
    {
        warnings.push(opentide_core::codes::RISK_BAND.to_owned());
    }
    if rule_type == "eql"
        && let Some(query) = &query
        && eql_is_sequence(query)
        && let Some((_, maxspan_ms)) = eql_maxspan(query)
    {
        // A duration saturates at `u128::MAX` seconds: so do its milliseconds,
        // never wrapping into a small window (#1928).
        let lookback_ms = lookback_secs.saturating_mul(1000);
        let window_ms = interval_secs
            .saturating_add(lookback_secs)
            .saturating_mul(1000);
        if maxspan_ms > window_ms {
            warnings.push(opentide_core::codes::EQL_MAXSPAN_WINDOW.to_owned());
        } else if maxspan_ms > lookback_ms {
            warnings.push(opentide_core::codes::EQL_MAXSPAN_LOOKBACK.to_owned());
        }
    }
    if !suppression && block.get("suppression").is_some_and(|s| !s.is_null()) {
        warnings.push("suppression_omitted_basic_license".to_owned());
    }
    if non_enterprise {
        warnings.push(opentide_core::codes::TECHNIQUE_NOT_ENTERPRISE.to_owned());
    }
    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The JSON text `text` as a rule body.
    fn rule_json(text: &str) -> Json {
        Json::parse(text).unwrap()
    }

    /// A rule Kibana holds as a replace would leave it is not written again
    /// (#1711): the fields Kibana writes itself, empty defaults, nested
    /// empties and a number's form are not differences; a changed value, a
    /// field opentide no longer sends that still holds a value, or a field
    /// the tenant lacks are.
    #[test]
    fn a_rule_is_held_when_a_replace_would_change_nothing() {
        let sent = r#"{"rule_id": "r", "type": "query", "name": "N", "risk_score": 73,
            "threat": [{"framework": "MITRE ATT&CK", "technique": [{"id": "T1059"}]}],
            "enabled": true}"#;
        let held = r#"{"id": "kb-1", "rule_id": "r", "type": "query", "name": "N",
            "risk_score": 73.0, "enabled": true, "revision": 4, "version": 2,
            "created_at": "x", "updated_at": "y", "immutable": false,
            "rule_source": {"type": "internal"}, "max_signals": 100, "interval": "5m",
            "references": [], "risk_score_mapping": [], "note": "",
            "threat": [{"framework": "MITRE ATT&CK", "technique": [{"id": "T1059", "subtechnique": []}]}]}"#;
        assert!(holds(&rule_json(held), &rule_json(sent)));
        let changed = held.replace(r#""name": "N""#, r#""name": "Old""#);
        assert!(!holds(&rule_json(&changed), &rule_json(sent)));
        // A field the rule no longer sends keeps its value until replaced.
        let stale = held.replace(r#""note": """#, r#""note": "old note""#);
        assert!(!holds(&rule_json(&stale), &rule_json(sent)));
        let raised = held.replace(r#""max_signals": 100"#, r#""max_signals": 500"#);
        assert!(!holds(&rule_json(&raised), &rule_json(sent)));
        let missing = held.replace(r#""risk_score": 73.0, "#, "");
        assert!(!holds(&rule_json(&missing), &rule_json(sent)));
        let more = held.replace(
            r#""technique": [{"id": "T1059", "subtechnique": []}]"#,
            r#""technique": [{"id": "T1059"}, {"id": "T1027"}]"#,
        );
        assert!(!holds(&rule_json(&more), &rule_json(sent)));
    }

    /// #1142: a rule write Kibana answers with a redirect the client could
    /// not follow fails the rule; a 2xx is written.
    #[test]
    fn a_redirect_answer_is_no_rule_written() {
        let answer = |status: u16| crate::answer::Answer {
            status,
            content_type: None,
            body: br#"{"message": "moved"}"#.to_vec(),
            elapsed: std::time::Duration::ZERO,
            credentials: crate::answer::Credentials::default(),
        };
        assert!(matches!(
            write_failed(&answer(307), "create_elastic_rule_failed", "lab"),
            Ok(Some(Deployed::Failed {
                status: Some(307),
                ..
            }))
        ));
        assert!(matches!(
            write_failed(&answer(200), "create_elastic_rule_failed", "lab"),
            Ok(None)
        ));
    }

    /// RC2-3: only Elasticsearch's own 404 for the index read is no data.
    #[test]
    fn only_a_missing_index_answer_is_index_not_found() {
        let answer = |status: u16, body: &str| crate::answer::Answer {
            status,
            content_type: None,
            body: body.as_bytes().to_vec(),
            elapsed: std::time::Duration::ZERO,
            credentials: crate::answer::Credentials::default(),
        };
        let found = |status: u16, body: &str| is_index_not_found(&answer(status, body), "idx");
        let missing = r#"{"error":{"root_cause":[{"type":"index_not_found_exception","reason":"no such index [idx]","resource.id":"idx","index":"idx"}],"type":"index_not_found_exception","index":"idx","resource.id":"idx"},"status":404}"#;
        assert!(found(404, missing));
        // The type only in the root cause, as a wrapped error has it, and an
        // error that names no index.
        let wrapped = r#"{"error":{"root_cause":[{"type":"index_not_found_exception"}],"type":"search_phase_execution_exception"}}"#;
        assert!(found(404, wrapped));
        assert!(found(
            404,
            r#"{"error":{"type":"index_not_found_exception","reason":"no such index [idx]"}}"#
        ));
        // The same body under another status, another 404, and no JSON.
        assert!(!found(200, missing));
        assert!(!found(400, missing));
        assert!(!found(
            404,
            r#"{"error":{"type":"resource_not_found_exception"}}"#
        ));
        assert!(!found(404, r#"{"message":"Not Found"}"#));
        assert!(!found(404, "<html>404</html>"));
        assert!(!found(404, r#"{"error":"index_not_found_exception"}"#));
        // A missing index the request did not name, by `index` or `resource.id`.
        let other = r#"{"error":{"type":"index_not_found_exception","index":"other","resource.id":"other"}}"#;
        assert!(!found(404, other));
        assert!(!found(
            404,
            r#"{"error":{"type":"index_not_found_exception","resource.id":"other"}}"#
        ));
        assert!(!found(
            404,
            r#"{"error":{"root_cause":[{"type":"index_not_found_exception","index":"other"}],"type":"x"}}"#
        ));
    }

    #[test]
    fn an_error_payload_does_not_quote_the_bearer() {
        use crate::answer::{TEST_BEARER, answer_to_bearer};
        let answer = answer_to_bearer(&format!(
            r#"{{"error":{{"type":"t","reason":"bad {TEST_BEARER}"}}}}"#
        ));
        let (kind, reason, blob) = error_payload(&answer);
        assert_eq!((kind.as_str(), reason.as_str()), ("t", "bad ***"));
        assert!(!blob.contains(TEST_BEARER), "{blob}");
    }

    #[test]
    fn a_refused_query_does_not_quote_the_bearer() {
        use crate::answer::{TEST_BEARER, answer_to_bearer};
        let refused = |body: &str| match body_of(body).unwrap_err() {
            ConnectorError::Refused { detail, .. } => detail.unwrap(),
            other => panic!("{other:?}"),
        };
        fn body_of(text: &str) -> Result<Json, ConnectorError> {
            body(&answer_to_bearer(text), "t", "ES|QL")
        }
        for (body, reason) in [
            (
                r#"{"error":{"root_cause":[{"reason":"r TOKEN"}]}}"#,
                "r ***",
            ),
            (r#"{"error":{"reason":"e TOKEN"}}"#, "e ***"),
            (r#"{"error":"plain TOKEN"}"#, "plain ***"),
            (r#"{"message":"m TOKEN"}"#, "m ***"),
        ] {
            assert_eq!(refused(&body.replace("TOKEN", TEST_BEARER)), reason);
        }
    }

    #[test]
    fn kibana_errors_do_not_quote_the_bearer() {
        use crate::answer::{TEST_BEARER, answer_to_bearer};
        let answer = answer_to_bearer(&format!(r#"{{"message":"no access for {TEST_BEARER}"}}"#));
        assert_eq!(kibana_error(&answer), "no access for ***");
    }

    #[test]
    fn query_text_is_read_past_comments_and_strings() {
        assert_eq!(
            esql_sources("FROM logs-* METADATA _id, _version | LIMIT 1"),
            "logs-*"
        );
        assert_eq!(
            esql_sources("SET a = 1; FROM \"l1\", `l2` // x\n| WHERE 1"),
            "l1,l2"
        );
        assert_eq!(
            esql_sources("FROM logs-metadata-*, (FROM x) | x"),
            "logs-metadata-*"
        );
        assert_eq!(esql_sources("ROW 1"), "");
        assert_eq!(
            esql_with_limit("FROM a // | LIMIT 3", 1),
            "FROM a // | LIMIT 3\n| LIMIT 2"
        );
        assert_eq!(esql_with_limit("FROM a | limit 3", 1), "FROM a | limit 3");
        assert!(esql_has_metadata_id("FROM a METADATA _index, _id | x"));
        assert!(!esql_has_metadata_id(
            "FROM a | WHERE m == \"METADATA _id\""
        ));
        assert!(esql_aggregates("FROM a | STATS c = COUNT(*)"));
        assert_eq!(
            eql_maxspan("sequence with maxspan=5m [a] [b]"),
            Some(("5m".into(), 300_000))
        );
        assert!(eql_is_sequence(" /* c */ sequence [a] [b]"));
        assert_eq!(mask_query("a \"é\" b", false), "a \"  \" b");
    }

    #[test]
    fn advisory_bands_and_legacy_events() {
        assert_eq!(risk_band("high"), Some((48, 73)));
        assert_eq!(risk_band("none"), None);
        assert_eq!(
            legacy_event("threshold_lookback"),
            "elastic_lookback_long_warning"
        );
        assert_eq!(legacy_event("risk_band"), "elastic_risk_score_band_warning");
        assert_eq!(legacy_event("other"), "");
    }

    #[test]
    fn advisories_name_the_codes() {
        let block: Json = serde_json::from_str(
            r#"{"type": "eql", "query": "sequence with maxspan=1h [a] [b]", "scheduling": {"interval": "5m", "lookback": "0m"}, "risk": 90, "suppression": {"group_by": ["a"]}}"#,
        )
        .unwrap_or(Json::Null);
        assert_eq!(
            advisories(&block, "high", false, true).unwrap_or_default(),
            [
                "lookback_zero",
                "risk_band",
                "eql_maxspan_window",
                "suppression_omitted_basic_license",
                "technique_not_enterprise"
            ]
        );
    }

    /// A lookback too long for its milliseconds saturates instead of
    /// wrapping into a small window that a short maxspan exceeds (#1928).
    #[test]
    fn advisories_saturate_a_huge_lookback() {
        let days = "9".repeat(40);
        let block: Json = serde_json::from_str(&format!(
            r#"{{"type": "eql", "query": "sequence with maxspan=1h [a] [b]", "scheduling": {{"interval": "5m", "lookback": "{days}d"}}}}"#
        ))
        .unwrap_or(Json::Null);
        assert_eq!(
            advisories(&block, "high", true, false).unwrap_or_default(),
            ["lookback_long"]
        );
    }
}
