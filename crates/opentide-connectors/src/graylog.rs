//! Graylog (graylog-1.0): event definitions through the REST API
//! (`/api/events/definitions`), the query check (`/api/search/validate`) and
//! the message search (`/api/search/messages`).
//!
//! A port of `platforms/graylog/{client,deployer,runner,validator}.py`,
//! request for request. Every call goes to `<url>/api/...` with `Accept:
//! application/json`, `X-Requested-By: opentide` and HTTP Basic
//! `<token>:token`. A 401 refuses the whole tenant; any other answer that is
//! not 2xx is this rule's failure.
//!
//! No retry is mounted: a create that got no answer is never sent again,
//! because titles are not unique and a retry may create a second definition
//! (`graylog_create_unconfirmed`).
//!
//! Deploy reads `GET /api/system` once per tenant before any write and builds
//! every body for that version ([`opentide_compile::graylog`]); before each
//! create and update, `POST /api/search/validate` checks the query, and a
//! query Graylog reports as `ERROR` is never saved. Deploy never lists
//! definitions and never calls `/execute`.

use std::sync::OnceLock;
use std::time::Duration;

use opentide_compile::Json;
use opentide_compile::graylog::{
    self, CompiledDefinition, MINIMUM_VERSION, VALIDATE_PATH, Version, create_body, create_path,
    delete_path, update_body, update_path, validate_body,
};
use regex::Regex;

use crate::answer::Answer;
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, LiveCheck, LiveValidator, Operation,
    Platform, QueryColumn, QueryOutcome, QueryRequest, QueryRunner, Row, TenantContext,
};
use crate::error::ConnectorError;
use crate::http::HttpSettings;
use crate::retry::RetryPolicy;

/// The platform's identifier.
pub const PLATFORM: &str = "graylog";

/// The server's own description.
pub const SYSTEM_PATH: &str = "/api/system";
/// The message search.
pub const MESSAGES_PATH: &str = "/api/search/messages";
/// The header Graylog requires on every write.
pub const REQUESTED_BY: &str = "opentide";

/// How a Graylog tenant is reached: 30 s, and no retry at all (a create that
/// got no answer must not be sent again).
pub fn http_defaults() -> HttpSettings {
    HttpSettings {
        timeout: Duration::from_secs(30),
        retry: RetryPolicy::none(),
        ..HttpSettings::default()
    }
}

fn immutable_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    #[expect(clippy::expect_used, reason = "a literal pattern, tested below")]
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?i)immutable entity cannot be modified|non-deletable entity cannot be deleted",
        )
        .expect("a valid pattern")
    })
}

fn in_use_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    #[expect(clippy::expect_used, reason = "a literal pattern, tested below")]
    PATTERN.get_or_init(|| {
        Regex::new(r"(?i)\bin use\b|\bdepend|\breferenced\b|\bused by\b").expect("a valid pattern")
    })
}

fn definition_id_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    #[expect(clippy::expect_used, reason = "a literal pattern, tested below")]
    PATTERN.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{24}$").expect("a valid pattern"))
}

/// A request that failed for this rule only (`GraylogApiError`): its method,
/// path and status, and Graylog's own message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    /// The request's method.
    pub method: String,
    /// The request's path.
    pub path: String,
    /// The answer's status.
    pub status: u16,
    /// Graylog's `message`, when it sent one.
    pub message: String,
    /// Graylog's `errors`, each field with its messages, sorted by field.
    pub errors: Vec<(String, Vec<String>)>,
}

impl ApiError {
    /// Graylog's message, with each refused field's messages (`detail`).
    pub fn detail(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if !self.message.is_empty() {
            parts.push(self.message.clone());
        }
        parts.extend(
            self.errors
                .iter()
                .map(|(name, messages)| format!("{name}: {}", messages.join("; "))),
        );
        if parts.is_empty() {
            "no detail given".to_owned()
        } else {
            parts.join(" | ")
        }
    }

    /// `404`.
    pub fn not_found(&self) -> bool {
        self.status == 404
    }

    /// `403`.
    pub fn forbidden(&self) -> bool {
        self.status == 403
    }

    /// "Immutable entity cannot be modified" or "Non-deletable entity cannot
    /// be deleted".
    pub fn immutable(&self) -> bool {
        immutable_pattern().is_match(&self.detail())
    }

    /// A `DELETE` refused because another definition depends on this one.
    pub fn in_use(&self) -> bool {
        self.method == "DELETE"
            && matches!(self.status, 400 | 409)
            && in_use_pattern().is_match(&self.detail())
    }

    /// A 400 with `{"errors": {<field>: [<message>]}}`: Graylog refused the
    /// body.
    pub fn invalid(&self) -> bool {
        self.status == 400 && !self.errors.is_empty()
    }

    /// The code the spec's failure table gives this answer (`_api_failure`).
    pub fn code(&self) -> &'static str {
        if self.immutable() {
            "graylog_definition_immutable"
        } else if self.in_use() {
            "graylog_definition_in_use"
        } else if self.forbidden() {
            "graylog_forbidden"
        } else if self.invalid() {
            "graylog_definition_invalid"
        } else {
            "graylog_request_failed"
        }
    }

    /// What the rule's failure says (`_api_failure`'s `error`).
    pub fn reason(&self) -> String {
        match self.code() {
            "graylog_definition_immutable" => format!(
                "{}; deploy never changes a definition's scope",
                self.detail()
            ),
            "graylog_definition_in_use" => {
                format!("another definition depends on this one: {}", self.detail())
            }
            "graylog_forbidden" => format!(
                "{} {} was refused (HTTP 403): {}. The token's user needs \
                 eventdefinitions:create, read, edit and delete, and streams:read on every \
                 stream the definition names",
                self.method,
                self.path,
                self.detail()
            ),
            "graylog_definition_invalid" => self.detail(),
            _ => self.to_string(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}: HTTP {}: {}",
            self.method,
            self.path,
            self.status,
            self.detail()
        )
    }
}

/// What failed: the rule ([`Failure::Rule`]) or the tenant.
#[derive(Debug)]
enum Failure {
    /// This rule's request failed; the run goes on to the next rule.
    Rule(ApiError),
    /// The tenant refused the token, runs a version opentide cannot deploy
    /// to, or could not be reached.
    Tenant(ConnectorError),
}

impl From<ConnectorError> for Failure {
    fn from(error: ConnectorError) -> Self {
        Self::Tenant(error)
    }
}

impl From<ApiError> for Failure {
    fn from(error: ApiError) -> Self {
        Self::Rule(error)
    }
}

/// Graylog's `errors` of an answer (`_errors`): each field's messages, by
/// field name.
fn errors_of(body: Option<&Json>) -> Vec<(String, Vec<String>)> {
    let Some(Json::Object(errors)) = body.and_then(|body| body.get("errors")) else {
        return Vec::new();
    };
    let mut found: Vec<(String, Vec<String>)> = errors
        .iter()
        .map(|(name, messages)| {
            let messages = match messages {
                Json::Array(items) => items.iter().map(text_of).collect(),
                other => vec![text_of(other)],
            };
            (name.clone(), messages)
        })
        .collect();
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

/// A JSON value as Python's `str()` writes it: a string as itself.
fn text_of(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        other => other.to_compact(),
    }
}

/// Graylog's `message` and `errors` of an answer; a body that is not JSON is
/// described instead (`_message`).
fn message_of(answer: &Answer) -> (String, Vec<(String, Vec<String>)>) {
    let Some(body) = answer.json() else {
        let described = answer
            .not_json_detail()
            .unwrap_or_else(|| format!("HTTP {}", answer.status));
        return (described, Vec::new());
    };
    let message = body
        .get("message")
        .filter(|message| message.truthy())
        .map(text_of)
        .unwrap_or_default();
    (message, errors_of(Some(&body)))
}

/// `error_type` values Graylog reports at WARNING level, each with its
/// opentide code (`WARNING_TYPES`).
pub const WARNING_TYPES: [(&str, &str); 3] = [
    ("UNKNOWN_FIELD", "graylog_unknown_field"),
    ("INVALID_VALUE_TYPE", "graylog_value_type"),
    ("INVALID_OPERATOR", "graylog_query_warning"),
];
/// Any other warning explanation.
pub const QUERY_WARNING: &str = "graylog_query_warning";
/// A query Graylog refuses.
pub const QUERY_INVALID: &str = "graylog_query_invalid";

/// One explanation as a line: its title and message, at Graylog's line and
/// column (`explanation_text`).
pub fn explanation_text(explanation: &Json) -> String {
    let Json::Object(_) = explanation else {
        return text_of(explanation);
    };
    let field = |key: &str| {
        explanation
            .get(key)
            .filter(|value| value.truthy())
            .map(|value| text_of(value).trim().to_owned())
            .filter(|text| !text.is_empty())
    };
    let title = field("error_title").or_else(|| field("error_type"));
    let message = field("error_message");
    let mut text = [title, message]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(": ");
    if text.is_empty() {
        "no detail given".clone_into(&mut text);
    }
    if let (Some(Json::Int(line)), Some(Json::Int(column))) = (
        explanation.get("begin_line"),
        explanation.get("begin_column"),
    ) {
        text.push_str(&format!(" (line {line}, column {column})"));
    }
    text
}

/// `(errors, warnings)` of a `/api/search/validate` answer (`read_verdict`).
///
/// `status: ERROR` makes its explanations errors, but for the types Graylog
/// reports as warnings (`UNKNOWN_FIELD`, `INVALID_VALUE_TYPE`); an ERROR with
/// no other explanation is one error. A WARNING or INFO explanation is a
/// `(code, text)` warning.
pub fn read_verdict(payload: &Json) -> (Vec<String>, Vec<(&'static str, String)>) {
    let status = payload
        .get("status")
        .filter(|status| status.truthy())
        .map_or_else(|| "OK".to_owned(), |status| text_of(status).to_uppercase());
    let explanations = match payload.get("explanations") {
        Some(Json::Array(items)) => items.as_slice(),
        _ => &[],
    };
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<(&'static str, String)> = Vec::new();
    for explanation in explanations {
        let kind = explanation
            .get("error_type")
            .filter(|kind| kind.truthy())
            .map(text_of)
            .unwrap_or_default();
        let warning = WARNING_TYPES
            .iter()
            .find(|(name, _)| *name == kind)
            .map(|(_, code)| *code);
        if status == "ERROR" && warning.is_none() {
            errors.push(explanation_text(explanation));
        } else {
            warnings.push((
                warning.unwrap_or(QUERY_WARNING),
                explanation_text(explanation),
            ));
        }
    }
    if status == "ERROR" && errors.is_empty() {
        errors.push("Graylog reports the query as ERROR".to_owned());
    }
    (errors, warnings)
}

/// The 24-hex `id` a create answered, lower-cased (`returned_id`).
pub fn returned_id(payload: Option<&Json>) -> Option<String> {
    let id = payload?.get("id")?.as_str()?.trim();
    definition_id_pattern()
        .is_match(id)
        .then(|| id.to_lowercase())
}

/// One tenant's client (`GraylogClient`).
#[derive(Debug, Clone, Copy)]
pub struct Client<'a> {
    cx: TenantContext<'a>,
}

impl<'a> Client<'a> {
    /// The tenant's client; its `url` and `token` are read when sent.
    pub fn new(cx: TenantContext<'a>) -> Self {
        Self { cx }
    }

    fn tenant(&self) -> &str {
        &self.cx.tenant.label.tenant
    }

    fn setup_error(&self, message: String) -> ConnectorError {
        ConnectorError::Setup {
            platform: PLATFORM.to_owned(),
            tenant: self.tenant().to_owned(),
            message,
        }
    }

    /// Sends one request; a 2xx answer is returned, a 401 refuses the
    /// tenant, any other status is the rule's [`ApiError`] (`request`).
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Json>,
        timeout: Option<Duration>,
    ) -> Result<Result<Answer, ApiError>, ConnectorError> {
        let base = self
            .cx
            .tenant
            .secret("url")?
            .expose()
            .trim_end_matches('/')
            .to_owned();
        let token = self.cx.tenant.secret("token")?;
        let mut builder = self
            .cx
            .http
            .request(method.clone(), &format!("{base}{path}"))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("X-Requested-By", REQUESTED_BY)
            .basic_auth(token.expose(), Some("token"));
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        if let Some(body) = body {
            builder = builder.body(
                serde_json::to_vec(body).map_err(|error| self.setup_error(error.to_string()))?,
            );
        }
        let request = builder
            .build()
            .map_err(|error| self.setup_error(crate::error::describe(error)))?;
        let answer = Answer::fetch(self.cx.http, request, self.cx.cancel).await?;
        if answer.status == 401 {
            return Err(ConnectorError::Authentication {
                platform: PLATFORM.to_owned(),
                tenant: self.tenant().to_owned(),
                message: format!(
                    "graylog_tenant_unauthorized: tenant {} refused the access token: HTTP 401",
                    self.tenant()
                ),
                detail: None,
            });
        }
        if !(200..300).contains(&answer.status) {
            let (message, errors) = message_of(&answer);
            return Ok(Err(ApiError {
                method: method.as_str().to_owned(),
                path: path.to_owned(),
                status: answer.status,
                message,
                errors,
            }));
        }
        Ok(Ok(answer))
    }

    /// The answer's JSON, or the rule's failure (`_json`).
    fn json(answer: &Answer, method: &reqwest::Method, path: &str) -> Result<Json, ApiError> {
        answer.json().ok_or_else(|| ApiError {
            method: method.as_str().to_owned(),
            path: path.to_owned(),
            status: answer.status,
            message: answer
                .not_json_detail()
                .unwrap_or_else(|| "not JSON".to_owned()),
            errors: Vec::new(),
        })
    }

    /// The server version (`GET /api/system`), which deploy reads once per
    /// tenant before any write (`version`).
    ///
    /// A version below 6.3, or none, refuses the tenant
    /// (`graylog_version_unsupported`).
    pub async fn version(&self) -> Result<Result<Version, ApiError>, ConnectorError> {
        let method = reqwest::Method::GET;
        let answer = match self.send(method.clone(), SYSTEM_PATH, None, None).await? {
            Ok(answer) => answer,
            Err(error) => return Ok(Err(error)),
        };
        let body = match Self::json(&answer, &method, SYSTEM_PATH) {
            Ok(body) => body,
            Err(error) => return Ok(Err(error)),
        };
        let raw = body.get("version").filter(|version| !version.is_null());
        let version = raw
            .and_then(Json::as_str)
            .and_then(graylog::parse_version)
            .filter(|version| *version >= MINIMUM_VERSION);
        match version {
            Some(version) => Ok(Ok(version)),
            None => {
                let shown = raw.map_or_else(
                    || "no version".to_owned(),
                    |raw| match raw {
                        Json::Str(text) => {
                            opentide_schema::configuration::repr::quote(text.as_str())
                        }
                        other => other.to_compact(),
                    },
                );
                Err(ConnectorError::Refused {
                    platform: PLATFORM.to_owned(),
                    tenant: self.tenant().to_owned(),
                    message: format!(
                        "graylog_version_unsupported: tenant {} runs Graylog {shown}; opentide \
                         deploys to Graylog 6.3 and later",
                        self.tenant()
                    ),
                    detail: None,
                })
            }
        }
    }

    /// `POST /api/search/validate`: Graylog's verdict on a query, nothing
    /// saved (`validate_query`).
    pub async fn validate_query(
        &self,
        body: &Json,
        timeout: Option<Duration>,
    ) -> Result<Result<Json, ApiError>, ConnectorError> {
        let method = reqwest::Method::POST;
        let answer = match self
            .send(method.clone(), VALIDATE_PATH, Some(body), timeout)
            .await?
        {
            Ok(answer) => answer,
            Err(error) => return Ok(Err(error)),
        };
        Ok(match Self::json(&answer, &method, VALIDATE_PATH) {
            Ok(payload @ Json::Object(_)) => Ok(payload),
            Ok(_) => Err(ApiError {
                method: method.as_str().to_owned(),
                path: VALIDATE_PATH.to_owned(),
                status: answer.status,
                message: "not an object".to_owned(),
                errors: Vec::new(),
            }),
            Err(error) => Err(error),
        })
    }

    /// `POST /api/search/messages`: rows for a query, read-only
    /// (`search_messages`).
    pub async fn search_messages(
        &self,
        body: &Json,
        timeout: Option<Duration>,
    ) -> Result<Result<Json, ApiError>, ConnectorError> {
        let method = reqwest::Method::POST;
        let answer = match self
            .send(method.clone(), MESSAGES_PATH, Some(body), timeout)
            .await?
        {
            Ok(answer) => answer,
            Err(error) => return Ok(Err(error)),
        };
        Ok(Self::json(&answer, &method, MESSAGES_PATH))
    }

    /// `POST /api/events/definitions?schedule=true`; the answer's JSON
    /// (`create`).
    ///
    /// `Ok(None)` for a 2xx whose body is not JSON (empty, or a proxy's
    /// page): the definition may exist, so the caller reports it
    /// unconfirmed, never as a failed request a later run would create
    /// again.
    pub async fn create(
        &self,
        body: &Json,
    ) -> Result<Result<Option<Json>, ApiError>, ConnectorError> {
        let answer = match self
            .send(reqwest::Method::POST, &create_path(), Some(body), None)
            .await?
        {
            Ok(answer) => answer,
            Err(error) => return Ok(Err(error)),
        };
        Ok(Ok(answer.json()))
    }

    /// `PUT /api/events/definitions/{id}?schedule=<enabled>` with the whole
    /// definition (`update`).
    pub async fn update(
        &self,
        definition_id: &str,
        body: &Json,
        enabled: bool,
    ) -> Result<Result<(), ApiError>, ConnectorError> {
        let path = update_path(definition_id, enabled);
        Ok(self
            .send(reqwest::Method::PUT, &path, Some(body), None)
            .await?
            .map(|_| ()))
    }

    /// `DELETE /api/events/definitions/{id}`: any 2xx, 204 for an id Graylog
    /// does not have (`delete`).
    pub async fn delete(
        &self,
        definition_id: &str,
    ) -> Result<Result<(), ApiError>, ConnectorError> {
        let path = delete_path(definition_id);
        Ok(self
            .send(reqwest::Method::DELETE, &path, None, None)
            .await?
            .map(|_| ()))
    }
}

/// What a deploy does to the definition on the tenant (`ExternalIdAction`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// No id is recorded: create the definition.
    Create,
    /// The recorded id: update it (or unschedule it).
    Update(String),
    /// The recorded id, under a DELETION status: delete it.
    Delete(String),
}

/// One rule to deploy to one tenant.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleDeploy {
    /// What to do.
    pub action: Action,
    /// The definition `opentide-compile` built for the tenant's version.
    pub compiled: CompiledDefinition,
    /// Whether the block's status is a DISABLEMENT: the definition is saved
    /// unscheduled, and its query is not checked (graylog-1.1), so a rule
    /// stays disableable after Graylog starts refusing its query.
    pub disable: bool,
    /// Why deployment state cannot take a definition created again, when it
    /// cannot (`deployment_state_ignore`, `unpersisted_error`): a recorded
    /// definition the tenant lost is then not created again.
    pub recreate_refusal: Option<String>,
}

/// What deployment state makes of a deploy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateChange {
    /// Nothing changes.
    Keep,
    /// Record the id Graylog gave the definition (`record_created`).
    Record(String),
    /// Forget the definition's id (`record_deleted`).
    Forget,
}

/// A warning a deploy raises (`DEPLOYMENT_WARNING_RAISED`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// The event (`graylog_definition_recreated`, `graylog_query_warning`).
    pub event: &'static str,
    /// What happened.
    pub detail: String,
}

/// A rule's failure: its code and what it says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleFailure {
    /// The code (`graylog_request_failed`, `graylog_query_invalid`,
    /// `graylog_create_unconfirmed`).
    pub code: &'static str,
    /// What it says.
    pub reason: String,
    /// The answer's status, when there was one.
    pub status: Option<u16>,
    /// What the tenant said, when it is worth logging on its own.
    pub detail: Option<String>,
}

/// What a deploy of one rule did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleOutcome {
    /// The deployment-state change.
    pub state: StateChange,
    /// Warnings raised.
    pub warnings: Vec<Warning>,
    /// The rule's failure.
    pub failure: Option<RuleFailure>,
    /// What was logged on success (`graylog_definition_created`,
    /// `_updated`, `_deleted`) and the definition's id.
    pub event: Option<(&'static str, String)>,
}

impl RuleOutcome {
    fn new() -> Self {
        Self {
            state: StateChange::Keep,
            warnings: Vec::new(),
            failure: None,
            event: None,
        }
    }
}

fn failed(error: &ApiError) -> RuleFailure {
    RuleFailure {
        code: error.code(),
        reason: error.reason(),
        status: Some(error.status),
        detail: None,
    }
}

/// Deploys one rule (`GraylogDeploy.deploy_rule`). A rule's failure is in the
/// outcome; an `Err` is the tenant's (a refused token, an unsupported
/// version, an unreachable tenant), which stops the tenant.
pub async fn deploy_rule(
    cx: TenantContext<'_>,
    rule: &RuleDeploy,
) -> Result<RuleOutcome, ConnectorError> {
    let client = Client::new(cx);
    let mut outcome = RuleOutcome::new();
    match run(&client, rule, &mut outcome).await {
        Ok(()) => Ok(outcome),
        Err(Failure::Rule(error)) => {
            outcome.failure = Some(failed(&error));
            Ok(outcome)
        }
        Err(Failure::Tenant(error)) => Err(error),
    }
}

async fn run(
    client: &Client<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), Failure> {
    let definition_id = match &rule.action {
        Action::Delete(definition_id) => {
            client.delete(definition_id).await??;
            outcome.state = StateChange::Forget;
            outcome.event = Some(("graylog_definition_deleted", definition_id.clone()));
            return Ok(());
        }
        Action::Create => None,
        Action::Update(definition_id) => Some(definition_id.clone()),
    };
    let enabled = !rule.disable;
    // A DISABLEMENT skips the query check (graylog-1.1): an unscheduled
    // definition never runs its query.
    if enabled && !query_accepted(client, &rule.compiled, outcome).await? {
        return Ok(());
    }
    let Some(definition_id) = definition_id else {
        return create(client, rule, outcome).await;
    };
    let body = update_body(&rule.compiled, &definition_id);
    match client.update(&definition_id, &body, enabled).await? {
        Ok(()) => {
            outcome.event = Some(("graylog_definition_updated", definition_id));
            Ok(())
        }
        Err(error) if error.not_found() => recreate(client, rule, outcome).await,
        Err(error) => Err(Failure::Rule(error)),
    }
}

/// Graylog's verdict on the query, before anything is saved: `false` on
/// `ERROR` (`_query_accepted`).
async fn query_accepted(
    client: &Client<'_>,
    compiled: &CompiledDefinition,
    outcome: &mut RuleOutcome,
) -> Result<bool, Failure> {
    let verdict = client
        .validate_query(&validate_body(compiled), None)
        .await??;
    let (errors, warnings) = read_verdict(&verdict);
    for (code, detail) in warnings {
        outcome.warnings.push(Warning {
            event: code,
            detail,
        });
    }
    if errors.is_empty() {
        return Ok(true);
    }
    outcome.failure = Some(RuleFailure {
        code: QUERY_INVALID,
        reason: format!(
            "Graylog refuses the query, so nothing is saved: {}",
            errors.join("; ")
        ),
        status: None,
        detail: None,
    });
    Ok(false)
}

async fn create(
    client: &Client<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), Failure> {
    let compiled = &rule.compiled;
    let answer = match client.create(&create_body(compiled)).await {
        Ok(Ok(answer)) => answer,
        Ok(Err(error)) => return Err(Failure::Rule(error)),
        // No answer: the create may have happened. Titles are not unique, so
        // a retry could create a second definition; it is never retried.
        Err(
            error @ (ConnectorError::Unreachable { .. }
            | ConnectorError::Timeout { .. }
            | ConnectorError::Answer { .. }),
        ) => {
            outcome.failure = Some(create_unconfirmed(compiled, &error.to_string()));
            return Ok(());
        }
        Err(error) => return Err(Failure::Tenant(error)),
    };
    let Some(definition_id) = returned_id(answer.as_ref()) else {
        outcome.failure = Some(RuleFailure {
            code: "graylog_create_unconfirmed",
            reason: format!(
                "the create of {} answered no 24-hex id, so the definition may exist without a \
                 binding; find it in Graylog, then delete it or record its id in \
                 .opentide/states/deployment/",
                opentide_schema::configuration::repr::quote(&compiled.title)
            ),
            status: None,
            detail: None,
        });
        return Ok(());
    };
    outcome.state = StateChange::Record(definition_id.clone());
    outcome.event = Some(("graylog_definition_created", definition_id));
    Ok(())
}

/// The bound definition is gone (404): create it again, or forget it under a
/// DISABLEMENT (`_recreate`).
async fn recreate(
    client: &Client<'_>,
    rule: &RuleDeploy,
    outcome: &mut RuleOutcome,
) -> Result<(), Failure> {
    if rule.disable {
        outcome.warnings.push(Warning {
            event: "graylog_definition_missing",
            detail: "the recorded definition no longer exists on the tenant; its id is removed"
                .to_owned(),
        });
        outcome.state = StateChange::Forget;
        return Ok(());
    }
    outcome.warnings.push(Warning {
        event: "graylog_definition_recreated",
        detail: "the recorded definition no longer exists on the tenant; creating it again"
            .to_owned(),
    });
    if let Some(refusal) = &rule.recreate_refusal {
        outcome.failure = Some(RuleFailure {
            code: "graylog_request_failed",
            reason: refusal.clone(),
            status: None,
            detail: None,
        });
        return Ok(());
    }
    create(client, rule, outcome).await
}

/// What a create that got no answer reports: the definition may exist with an
/// id opentide does not know, and a retry could create a second one
/// (`graylog_create_unconfirmed`).
pub fn create_unconfirmed(compiled: &CompiledDefinition, detail: &str) -> RuleFailure {
    let mut found_by = format!(
        "the title {}",
        opentide_schema::configuration::repr::quote(&compiled.title)
    );
    if let Some(tag) = compiled.uuid_tag() {
        found_by.push_str(&format!(
            " or the tag {}",
            opentide_schema::configuration::repr::quote(&tag)
        ));
    }
    RuleFailure {
        code: "graylog_create_unconfirmed",
        reason: format!(
            "the create got no answer, so it may have succeeded with an id opentide does not \
             know. Find the definition by {found_by} in Graylog, then delete it or record its id \
             in .opentide/states/deployment/"
        ),
        status: None,
        detail: Some(detail.to_owned()),
    }
}

// --- queries ---------------------------------------------------------------------

/// Fields every search asks for before 7.2, where Graylog returns only the
/// fields it is asked for (`_BASE_FIELDS`).
pub const BASE_FIELDS: [&str; 3] = ["timestamp", "source", "message"];
/// Graylog's placeholder for a field a message does not have.
pub const MISSING: &str = "-";

fn query_field_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    #[expect(clippy::expect_used, reason = "a literal pattern, tested below")]
    PATTERN.get_or_init(|| {
        Regex::new(r"(?:^|[^\w.@\\-])(?:_exists_:)?([A-Za-z0-9_@-]+(?:\.[A-Za-z0-9_@-]+)*):")
            .expect("a valid pattern")
    })
}

fn stream_id_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    #[expect(clippy::expect_used, reason = "a literal pattern, tested below")]
    PATTERN.get_or_init(|| Regex::new(r"^[0-9a-f]{24}$").expect("a valid pattern"))
}

/// The `fields` a search asks for: none on 7.2+, where Graylog returns every
/// field (`requested_fields`).
///
/// Before 7.2 Graylog returns only the fields it is asked for: the message's
/// timestamp, source and message, and the fields the query names. On 6.3 and
/// 7.0, Graylog splits a requested name on `.`, so a dotted field is not
/// asked for.
pub fn requested_fields(query: &str, version: Version) -> Option<Vec<String>> {
    if version >= Version(7, 2, 0) {
        return None;
    }
    let mut fields: Vec<String> = BASE_FIELDS
        .iter()
        .map(|field| (*field).to_owned())
        .collect();
    for captures in query_field_pattern().captures_iter(query) {
        let Some(name) = captures.get(1).map(|name| name.as_str()) else {
            continue;
        };
        if name == "_exists_" || fields.iter().any(|field| field == name) {
            continue;
        }
        if name.contains('.') && version < Version(7, 1, 0) {
            continue;
        }
        fields.push(name.to_owned());
    }
    Some(fields)
}

/// Stream ids for `aliases` (or the tenant's `streams` when there are none),
/// from the tenant's `stream_ids` table (`resolve_streams`).
///
/// A 24-hex value is a stream id already. An alias the tenant does not define
/// is `graylog_alias_unknown`.
pub fn resolve_streams(
    cx: TenantContext<'_>,
    aliases: &[String],
) -> Result<Vec<String>, ConnectorError> {
    let names: Vec<String> = if aliases.is_empty() {
        cx.tenant.list("streams").to_vec()
    } else {
        aliases.to_vec()
    };
    let table = cx.tenant.table("stream_ids");
    let id_of = |name: &str| {
        table
            .iter()
            .find(|(alias, _)| alias == name)
            .map(|(_, id)| id.clone())
    };
    let unknown: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| id_of(name).is_none() && !stream_id_pattern().is_match(name))
        .collect();
    if !unknown.is_empty() {
        return Err(ConnectorError::Refused {
            platform: PLATFORM.to_owned(),
            tenant: cx.tenant.label.tenant.clone(),
            message: format!(
                "graylog_alias_unknown: stream alias(es) {} are not in tenant {}'s stream_ids \
                 table",
                unknown.join(", "),
                cx.tenant.label.tenant
            ),
            detail: None,
        });
    }
    Ok(names
        .iter()
        .map(|name| id_of(name).unwrap_or_else(|| name.clone()))
        .collect())
}

/// The columns and rows of a `/api/search/messages` answer (`_rows`): a value
/// Graylog left out (`-`) or null is not in its row.
pub fn read_rows(payload: &Json) -> (Vec<QueryColumn>, Vec<Row>) {
    let schema = match payload.get("schema") {
        Some(Json::Array(schema)) => schema.as_slice(),
        _ => &[],
    };
    let columns: Vec<QueryColumn> = schema
        .iter()
        .filter(|entry| matches!(entry, Json::Object(_)))
        .map(|entry| {
            let name = entry
                .get("field")
                .filter(|name| name.truthy())
                .or_else(|| entry.get("name"))
                .map(text_of)
                .unwrap_or_default();
            QueryColumn {
                name,
                kind: entry.get("type").and_then(Json::as_str).map(str::to_owned),
            }
        })
        .collect();
    let datarows = match payload.get("datarows") {
        Some(Json::Array(rows)) => rows.as_slice(),
        _ => &[],
    };
    let mut rows: Vec<Row> = Vec::new();
    for datarow in datarows {
        let Json::Array(values) = datarow else {
            continue;
        };
        let mut row = Row::new();
        for (column, value) in columns.iter().zip(values) {
            if value.is_null() || value.as_str() == Some(MISSING) {
                continue;
            }
            row.insert(column.name.clone(), value.clone());
        }
        rows.push(row);
    }
    (columns, rows)
}

fn refused(cx: TenantContext<'_>, error: &ApiError) -> ConnectorError {
    ConnectorError::Refused {
        platform: PLATFORM.to_owned(),
        tenant: cx.tenant.label.tenant.clone(),
        message: format!("Graylog refused the query on {}", cx.tenant.label.tenant),
        detail: Some(error.detail()),
    }
}

/// The platform: a deployer, a live validator and a query runner.
#[derive(Debug, Default)]
pub struct Graylog;

impl Deployer for Graylog {
    /// One rule, from the compiled create body alone: the definition is read
    /// back from it, and the version it was built for is the body's shape
    /// (6.3 is flat, 7.x wraps it in `entity`). [`deploy_rule`] takes the
    /// compiled definition itself.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        Box::pin(async move {
            let body: Json =
                serde_json::from_slice(&request.body).map_err(|error| ConnectorError::Setup {
                    platform: PLATFORM.to_owned(),
                    tenant: cx.tenant.label.tenant.clone(),
                    message: format!("the compiled body is not JSON: {error}"),
                })?;
            let wrapped = body.get("entity").is_some();
            let definition = body.get("entity").unwrap_or(&body);
            let Json::Object(definition) = definition else {
                return Err(ConnectorError::Setup {
                    platform: PLATFORM.to_owned(),
                    tenant: cx.tenant.label.tenant.clone(),
                    message: "the compiled body carries no event definition".to_owned(),
                });
            };
            let compiled = CompiledDefinition {
                uuid: request.rule_id.clone(),
                title: definition
                    .get("title")
                    .and_then(Json::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                version: if wrapped {
                    graylog::PREVIEW_VERSION
                } else {
                    Version(6, 3, 0)
                },
                definition: definition.clone(),
                warnings: Vec::new(),
                unresolved: Vec::new(),
            };
            let rule = RuleDeploy {
                action: match request.operation {
                    Operation::Create => Action::Create,
                    Operation::Update | Operation::Disable => {
                        Action::Update(request.rule_id.clone())
                    }
                    Operation::Delete => Action::Delete(request.rule_id.clone()),
                },
                compiled,
                disable: request.operation == Operation::Disable,
                recreate_refusal: None,
            };
            let outcome = deploy_rule(cx, &rule).await?;
            if let Some(failure) = outcome.failure {
                return Err(ConnectorError::Refused {
                    platform: PLATFORM.to_owned(),
                    tenant: cx.tenant.label.tenant.clone(),
                    message: format!("{}: {}", failure.code, failure.reason),
                    detail: failure.detail,
                });
            }
            Ok(DeployOutcome {
                remote_id: match outcome.state {
                    StateChange::Record(id) => Some(id),
                    StateChange::Keep => Some(request.rule_id.clone()),
                    StateChange::Forget => None,
                },
                operation: request.operation,
            })
        })
    }
}

impl LiveValidator for Graylog {
    /// `POST /api/search/validate` over the request's window: the query is
    /// parsed against the streams' field mappings and no search runs
    /// (`GraylogQueryRunner.check`). `ERROR` explanations refuse the query;
    /// `WARNING` and `INFO` ones are the check's warnings, each with
    /// Graylog's line and column.
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        Box::pin(async move {
            let client = Client::new(cx);
            let mut body = opentide_compile::json::Object::new();
            body.insert("query".into(), request.text.clone().into());
            body.insert(
                "streams".into(),
                Json::Array(
                    resolve_streams(cx, &request.index)?
                        .into_iter()
                        .map(Json::Str)
                        .collect(),
                ),
            );
            let mut timerange = opentide_compile::json::Object::new();
            timerange.insert("type".into(), "relative".into());
            timerange.insert("range".into(), Json::Int(request.window.seconds()));
            body.insert("timerange".into(), Json::Object(timerange));
            let verdict = client
                .validate_query(&Json::Object(body), Some(request.timeout))
                .await?
                .map_err(|error| refused(cx, &error))?;
            let (errors, warnings) = read_verdict(&verdict);
            if !errors.is_empty() {
                return Err(ConnectorError::Refused {
                    platform: PLATFORM.to_owned(),
                    tenant: cx.tenant.label.tenant.clone(),
                    message: format!("Graylog refused the query on {}", cx.tenant.label.tenant),
                    detail: Some(errors.join("; ")),
                });
            }
            Ok(LiveCheck {
                result: None,
                errors: Vec::new(),
                warnings: warnings
                    .into_iter()
                    .map(|(code, text)| format!("{code}: {text}"))
                    .collect(),
            })
        })
    }
}

impl QueryRunner for Graylog {
    /// `POST /api/search/messages`, which reads messages and saves nothing
    /// (`GraylogQueryRunner.run`): the newest rows first, one more than the
    /// limit to tell a cut, and `--index` as stream aliases.
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        Box::pin(async move {
            let client = Client::new(cx);
            let streams = resolve_streams(cx, &request.index)?;
            let mut body = opentide_compile::json::Object::new();
            body.insert("query".into(), request.text.clone().into());
            body.insert(
                "streams".into(),
                Json::Array(streams.into_iter().map(Json::Str).collect()),
            );
            let mut timerange = opentide_compile::json::Object::new();
            timerange.insert("type".into(), "absolute".into());
            timerange.insert(
                "from".into(),
                crate::connector::utc_z(request.window.start).into(),
            );
            timerange.insert(
                "to".into(),
                crate::connector::utc_z(request.window.end).into(),
            );
            body.insert("timerange".into(), Json::Object(timerange));
            body.insert(
                "size".into(),
                Json::Int(i64::try_from(request.limit.saturating_add(1)).unwrap_or(i64::MAX)),
            );
            body.insert("sort".into(), "timestamp".into());
            body.insert("sort_order".into(), "desc".into());
            let version = client
                .version()
                .await?
                .map_err(|error| refused(cx, &error))?;
            if let Some(fields) = requested_fields(&request.text, version) {
                body.insert(
                    "fields".into(),
                    Json::Array(fields.into_iter().map(Json::Str).collect()),
                );
            }
            let payload = client
                .search_messages(&Json::Object(body), Some(request.timeout))
                .await?
                .map_err(|error| refused(cx, &error))?;
            let (columns, rows) = read_rows(&payload);
            let truncated = rows.len() > request.limit;
            Ok(QueryOutcome {
                columns,
                rows: rows.into_iter().take(request.limit).collect(),
                truncated,
                language: Some("lucene".to_owned()),
                ..QueryOutcome::default()
            })
        })
    }
}

impl Platform for Graylog {
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

    fn api(method: &str, status: u16, message: &str) -> ApiError {
        ApiError {
            method: method.to_owned(),
            path: "/api/events/definitions/x".to_owned(),
            status,
            message: message.to_owned(),
            errors: Vec::new(),
        }
    }

    #[test]
    fn the_failure_table() {
        assert_eq!(
            api("PUT", 400, "Immutable entity cannot be modified").code(),
            "graylog_definition_immutable"
        );
        assert_eq!(
            api("DELETE", 400, "Non-deletable entity cannot be deleted").code(),
            "graylog_definition_immutable"
        );
        assert_eq!(
            api("DELETE", 409, "the definition is in use").code(),
            "graylog_definition_in_use"
        );
        // Only a DELETE is "in use".
        assert_eq!(
            api("PUT", 409, "the definition is in use").code(),
            "graylog_request_failed"
        );
        assert_eq!(api("PUT", 403, "no").code(), "graylog_forbidden");
        let mut invalid = api("POST", 400, "");
        invalid.errors = vec![("config.query".to_owned(), vec!["bad".to_owned()])];
        assert_eq!(invalid.code(), "graylog_definition_invalid");
        assert_eq!(invalid.detail(), "config.query: bad");
        assert_eq!(api("POST", 500, "").code(), "graylog_request_failed");
        assert_eq!(api("POST", 500, "").detail(), "no detail given");
        assert_eq!(
            api("POST", 500, "").to_string(),
            "POST /api/events/definitions/x: HTTP 500: no detail given"
        );
    }

    #[test]
    fn verdicts() {
        let json = |text: &str| serde_json::from_str::<Json>(text).unwrap();
        let (errors, warnings) = read_verdict(&json(r#"{"status": "OK"}"#));
        assert!(errors.is_empty() && warnings.is_empty());
        let (errors, warnings) = read_verdict(&json(
            r#"{"status": "ERROR", "explanations": [
                {"error_type": "QUERY_PARSING_ERROR", "error_title": "Cannot parse",
                 "error_message": "unexpected `*`", "begin_line": 1, "begin_column": 7},
                {"error_type": "UNKNOWN_FIELD", "error_message": "no such field"}]}"#,
        ));
        assert_eq!(
            errors,
            ["Cannot parse: unexpected `*` (line 1, column 7)".to_owned()]
        );
        assert_eq!(
            warnings,
            [(
                "graylog_unknown_field",
                "UNKNOWN_FIELD: no such field".to_owned()
            )]
        );
        // An ERROR with no explanation of its own is still one error.
        let (errors, _) = read_verdict(&json(r#"{"status": "ERROR"}"#));
        assert_eq!(errors, ["Graylog reports the query as ERROR".to_owned()]);
        // A WARNING status makes every explanation a warning.
        let (errors, warnings) = read_verdict(&json(
            r#"{"status": "WARNING", "explanations": [{"error_type": "INVALID_OPERATOR"}]}"#,
        ));
        assert!(errors.is_empty());
        assert_eq!(
            warnings,
            [("graylog_query_warning", "INVALID_OPERATOR".to_owned())]
        );
    }

    #[test]
    fn created_ids() {
        let json = |text: &str| serde_json::from_str::<Json>(text).unwrap();
        assert_eq!(
            returned_id(Some(&json(r#"{"id": " 65F1C0DE2A3B4C5D6E7F8091 "}"#))).as_deref(),
            Some("65f1c0de2a3b4c5d6e7f8091")
        );
        assert_eq!(returned_id(Some(&json(r#"{"id": "short"}"#))), None);
        assert_eq!(returned_id(Some(&json("{}"))), None);
        assert_eq!(returned_id(None), None);
    }

    #[test]
    fn requested_fields_before_7_2() {
        let query = "EventID:1 AND winlog.event_data.User:bob AND _exists_:source";
        assert_eq!(requested_fields(query, Version(7, 2, 0)), None);
        assert_eq!(
            requested_fields(query, Version(7, 1, 0)).unwrap(),
            [
                "timestamp",
                "source",
                "message",
                "EventID",
                "winlog.event_data.User"
            ]
        );
        assert_eq!(
            requested_fields(query, Version(6, 3, 0)).unwrap(),
            ["timestamp", "source", "message", "EventID"]
        );
    }

    #[test]
    fn rows_leave_out_what_graylog_left_out() {
        let payload: Json = serde_json::from_str(
            r#"{"schema": [{"field": "timestamp", "type": "date"}, {"field": "source"},
                           {"field": "user"}],
                "datarows": [["2026-01-01T00:00:00Z", "host-1", "-"],
                             ["2026-01-02T00:00:00Z", "host-2", "bob"], "not a row"]}"#,
        )
        .unwrap();
        let (columns, rows) = read_rows(&payload);
        assert_eq!(columns.len(), 3);
        assert_eq!(columns[0].kind.as_deref(), Some("date"));
        assert_eq!(rows.len(), 2);
        assert!(!rows[0].contains_key("user"));
        assert_eq!(rows[1]["user"], Json::Str("bob".to_owned()));
    }

    #[test]
    fn an_unconfirmed_create_names_the_title_and_the_tag() {
        let definition = {
            let mut definition = opentide_compile::json::Object::new();
            definition.insert(
                "tags".into(),
                Json::Array(vec![Json::Str("opentide.u".to_owned())]),
            );
            definition
        };
        let compiled = CompiledDefinition {
            uuid: "u".to_owned(),
            title: "A rule".to_owned(),
            version: Version(7, 2, 0),
            definition,
            warnings: Vec::new(),
            unresolved: Vec::new(),
        };
        let failure = create_unconfirmed(&compiled, "connection reset");
        assert_eq!(failure.code, "graylog_create_unconfirmed");
        assert!(
            failure
                .reason
                .contains("the title \"A rule\" or the tag \"opentide.u\""),
            "{}",
            failure.reason
        );
        assert_eq!(failure.detail.as_deref(), Some("connection reset"));
    }
}
