//! The traits a platform implements, and the registry of platforms.
//!
//! A platform is a [`Platform`]: its identifier and the capabilities it has,
//! each a trait of its own, so a platform that cannot validate a query live
//! (CrowdStrike, HarfangLab, Sysdig) has no [`LiveValidator`] rather than
//! one that pretends. Every operation takes a [`TenantContext`] (the tenant,
//! its client, the run's cancellation) and returns a [`ConnectorError`] on
//! failure. The methods return boxed futures so a registry holds platforms
//! as trait objects; UC-4.2 to UC-4.4 implement them, and UC-4.5 adds the
//! Python plugin hook ([`crate::plugin`]): a plugin is a [`Platform`] too,
//! registered after the built-in ones, with a [`ConfigurationCheck`] of its
//! own for its block of a rule's `configurations`.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::error::ConnectorError;
use crate::{HttpClient, Tenant};

/// A future a connector returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What every operation on one tenant receives.
#[derive(Clone, Copy, Debug)]
pub struct TenantContext<'a> {
    /// The tenant.
    pub tenant: &'a Tenant,
    /// Its client.
    pub http: &'a HttpClient,
    /// Fires when the run is cancelled.
    pub cancel: &'a CancellationToken,
}

/// What a deploy does to one rule on one tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// The rule is new there.
    Create,
    /// The rule is there and changes.
    Update,
    /// The rule is there and is turned off.
    Disable,
    /// The rule is removed.
    Delete,
}

/// One compiled rule to deploy (the body `opentide-compile` built).
///
/// `#[non_exhaustive]`: build one with [`DeployRequest::new`],
/// [`DeployRequest::delete`], [`DeployRequest::with_policies`],
/// [`DeployRequest::at`] and [`DeployRequest::refusing_recreate`].
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct DeployRequest {
    /// The rule's identifier on the platform (its UUID or name).
    pub rule_id: String,
    /// What to do.
    pub operation: Operation,
    /// The request body, as `opentide-compile` wrote it: bytes, so the key
    /// order and layout the platform receives are the compiled ones.
    pub body: Vec<u8>,
    /// Sysdig's runtime policies for the rule: `None` takes the tenant's
    /// (its setup's `policies`), `Some` exactly these, as `opentide deploy`
    /// takes a block's own `policies` first (a deploy plan's Sysdig entry
    /// carries them). Other platforms read none.
    pub policies: Option<Vec<String>>,
    /// The time the deploy runs at, which a platform stamps on what it
    /// writes (Carbon Black Cloud's report `timestamp`): `None` is now. A run
    /// reads one clock for every rule, and a test fixes it.
    pub now: Option<jiff::Timestamp>,
    /// Why the rule must not be created again when the tenant lost it:
    /// `opentide deploy` sets it when deployment state cannot record the new
    /// id (`deployment_state_ignored`, `deployment_state_unpersisted`). A
    /// platform that finds a recorded rule gone then fails the rule with this
    /// failure instead of creating it. Sysdig's, Exabeam's, Bitdefender's,
    /// Graylog's and Google SecOps's failure keeps its `*_recreated` warning, raised
    /// before the refusal, in [`DeployError::partial`], as `opentide deploy`
    /// logs it; the other platforms' carry no warning yet. `None` creates it
    /// again.
    pub recreate_refusal: Option<DeployFailure>,
}

impl DeployRequest {
    /// `operation` on the rule `rule_id`, with the compiled `body`, and the
    /// tenant's Sysdig policies ([`DeployRequest::with_policies`] names
    /// others).
    pub fn new(rule_id: impl Into<String>, operation: Operation, body: impl Into<Vec<u8>>) -> Self {
        Self {
            rule_id: rule_id.into(),
            operation,
            body: body.into(),
            policies: None,
            now: None,
            recreate_refusal: None,
        }
    }

    /// The deletion of the rule `rule_id`: no body, which no platform but
    /// HarfangLab reads for a delete (Sysdig reads the rule's name from the
    /// tenant to take it out of its policies). A HarfangLab delete names the
    /// rule's kind: build it with `new(rule_id, Operation::Delete,
    /// br#"{"kind": "YARA"}"#.to_vec())`.
    pub fn delete(rule_id: impl Into<String>) -> Self {
        Self::new(rule_id, Operation::Delete, Vec::new())
    }

    /// The same request with Sysdig's runtime `policies`: `None` takes the
    /// tenant's, `Some` exactly these.
    #[must_use]
    pub fn with_policies(mut self, policies: Option<Vec<String>>) -> Self {
        self.policies = policies;
        self
    }

    /// The same request, run at `now` ([`DeployRequest::now`]).
    #[must_use]
    pub fn at(mut self, now: jiff::Timestamp) -> Self {
        self.now = Some(now);
        self
    }

    /// The same request, failing with `refusal` rather than creating again a
    /// rule the tenant lost ([`DeployRequest::recreate_refusal`]).
    #[must_use]
    pub fn refusing_recreate(mut self, refusal: DeployFailure) -> Self {
        self.recreate_refusal = Some(refusal);
        self
    }

    /// *error* as this request's recreate refusal when the platform failed
    /// the rule with it, so the failure keeps the refusal's code; any other
    /// error as it is. The platform refuses with the refusal's message, alone
    /// or after its code (`code: message`), as `opentide deploy` matches it;
    /// an empty message matches nothing.
    pub fn refused_recreate(&self, error: DeployError) -> DeployError {
        let refused_with = |refusal: &DeployFailure| {
            let message = &error.failure.message;
            !refusal.message.is_empty()
                && matches!(
                    error.connector.as_deref(),
                    Some(ConnectorError::Refused { .. })
                )
                && (*message == refusal.message
                    || message
                        .split_once(": ")
                        .is_some_and(|(_, rest)| rest == refusal.message))
        };
        match &self.recreate_refusal {
            Some(refusal) if refused_with(refusal) => {
                let mut failure = refusal.clone();
                for (key, value) in &error.failure.fields {
                    if failure.field(key).is_none() {
                        failure.fields.push((key.clone(), value.clone()));
                    }
                }
                DeployError {
                    scope: DeployScope::Rule,
                    failure,
                    connector: error.connector,
                    partial: error.partial,
                    more: error.more,
                }
            }
            _ => error,
        }
    }

    /// The time the deploy runs at: [`DeployRequest::now`], or now.
    pub fn time(&self) -> jiff::Timestamp {
        self.now.unwrap_or_else(jiff::Timestamp::now)
    }
}

/// What a deploy did.
///
/// `#[non_exhaustive]`: a [`Deployer`] outside this crate builds one with
/// [`DeployOutcome::new`] (and [`DeployOutcome::with_warnings`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeployOutcome {
    /// The platform's identifier of the rule, kept in deployment state.
    pub remote_id: Option<String>,
    /// What was done.
    pub operation: Operation,
    /// What the deploy raised without failing: the rule is deployed, and
    /// these say what to check (a rule created again because the tenant
    /// lost it, a partial deployment). `opentide deploy` logs each one and
    /// ends with its warnings exit code. A deploy that fails is a
    /// [`DeployError`], never an outcome: a failed deployment never looks
    /// like a deployed one.
    pub warnings: Vec<DeployWarning>,
    /// What the deploy did, as the events `opentide deploy` logs at info
    /// level (`sysdig_rule_created` with the rule's id): not warnings, and
    /// nothing to act on.
    pub events: Vec<DeployEvent>,
}

impl DeployOutcome {
    /// `operation` done, with the platform's identifier of the rule (`None`
    /// once it is deleted), and no warnings.
    pub fn new(remote_id: Option<String>, operation: Operation) -> Self {
        Self {
            remote_id,
            operation,
            warnings: Vec::new(),
            events: Vec::new(),
        }
    }

    /// The same outcome with `warnings`.
    #[must_use]
    pub fn with_warnings(mut self, warnings: Vec<DeployWarning>) -> Self {
        self.warnings = warnings;
        self
    }

    /// The same outcome with `events`.
    #[must_use]
    pub fn with_events(mut self, events: Vec<DeployEvent>) -> Self {
        self.events = events;
        self
    }

    /// Whether the tenant already held the rule as the request has it, so
    /// nothing was written (its [`RULE_UNCHANGED`] event, #1711).
    pub fn unchanged(&self) -> bool {
        self.events.iter().any(|event| event.name == RULE_UNCHANGED)
    }
}

/// The event of a deploy that wrote nothing: the tenant already held the
/// rule as the request has it, in every field the request sends
/// ([`DeployOutcome::unchanged`], #1711).
pub const RULE_UNCHANGED: &str = "rule_unchanged";

/// Something a deploy did, as an event: its name (`sysdig_rule_created`)
/// and the fields it is logged with, in order (`rule_id`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeployEvent {
    /// The event's name, as `opentide deploy` logs it.
    pub name: String,
    /// Its fields, in order.
    pub fields: Vec<(String, String)>,
}

impl DeployEvent {
    /// The event `name`, with no fields.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
        }
    }

    /// The same event with the field `key` set to `value` (after the fields
    /// it has).
    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push((key.into(), value.into()));
        self
    }
}

/// A warning a deploy raised: the rule is deployed, with something to check.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeployWarning {
    /// The event `opentide deploy` logs it as (`sysdig_rule_recreated`,
    /// `graylog_query_warning`).
    pub code: String,
    /// What happened.
    pub message: String,
    /// Whether it raises the run's warnings (`DEPLOYMENT_WARNING_RAISED`:
    /// `opentide deploy` ends with its warnings exit code). A warning that
    /// only says what was done (`splunk_alert_deleted`) is logged as one
    /// without raising them.
    pub raised: bool,
}

impl DeployWarning {
    /// The warning `code`, saying `message`, which raises the run's warnings.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            raised: true,
        }
    }

    /// The same warning, logged without raising the run's warnings.
    #[must_use]
    pub fn unraised(mut self) -> Self {
        self.raised = false;
        self
    }
}

/// What a failed deploy stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeployScope {
    /// The rule failed (the tenant refused it, or answered for it in a way
    /// opentide cannot read): the tenant's other rules can still deploy.
    Rule,
    /// The tenant cannot take any rule (unreachable, refused credentials, a
    /// setup it cannot use): its other rules would fail the same way.
    Tenant,
}

/// Why a deploy failed, as data: a stable code, the message, the HTTP
/// status when the tenant answered with one, and the fields that locate it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeployFailure {
    /// A stable code (`tenant_refused`, `tenant_unreachable`, or the
    /// platform's own, such as `sentinel_one_rule_not_found`).
    pub code: &'static str,
    /// What failed, in words; it names the tenant, never a credential.
    pub message: String,
    /// The HTTP status the tenant answered with, when it answered.
    pub status: Option<u16>,
    /// What locates the failure (`platform`, `tenant`, `address`, the
    /// vendor's `detail`), in order.
    pub fields: Vec<(String, String)>,
}

impl DeployFailure {
    /// The failure `code`, saying `message`, with no status or fields.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status: None,
            fields: Vec::new(),
        }
    }

    /// The same failure, with the HTTP `status` the tenant answered.
    #[must_use]
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// The same failure, with the field `key` set to `value` (after the
    /// fields it has).
    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push((key.into(), value.into()));
        self
    }

    /// The value of the field `key`.
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
}

/// A deploy that failed: a rule's failure as much as a tenant's. A
/// [`Deployer`] never reports a failed rule as a [`DeployOutcome`].
#[derive(Debug, thiserror::Error)]
#[error("{}", failure.message)]
#[non_exhaustive]
pub struct DeployError {
    /// What the failure stops: the rule, or every rule of the tenant.
    pub scope: DeployScope,
    /// Why, as data.
    pub failure: DeployFailure,
    /// The connector error it came from, when it came from one (an
    /// interrupt is [`ConnectorError::Cancelled`]); boxed, to keep the error
    /// small.
    pub connector: Option<Box<ConnectorError>>,
    /// What the deploy did before it failed, when it did something the
    /// caller must keep: its `remote_id` is an id the tenant gave the rule,
    /// which the caller records in its deployment state (a Sysdig rule
    /// created, then refused its runtime policies), or `None` when there is
    /// none to record; its warnings and events are those raised before the
    /// failure. `None` when the failure left nothing to keep. Sysdig fills
    /// it; the other platforms do as their deploy moves onto their
    /// `Deployer`.
    pub partial: Option<Box<DeployOutcome>>,
    /// The rule's further failures, in order, when one deploy failed more
    /// than once (a Google SecOps rule under a DISABLEMENT whose text could
    /// not be written, then `google_secops_deployment_failed`); `failure` is
    /// the first. Empty for most failures.
    pub more: Vec<DeployFailure>,
}

impl DeployError {
    /// A rule's failure.
    pub fn rule(failure: DeployFailure) -> Self {
        Self {
            scope: DeployScope::Rule,
            failure,
            connector: None,
            partial: None,
            more: Vec::new(),
        }
    }

    /// A tenant's failure: its other rules would fail the same way.
    pub fn tenant(failure: DeployFailure) -> Self {
        Self {
            scope: DeployScope::Tenant,
            failure,
            connector: None,
            partial: None,
            more: Vec::new(),
        }
    }

    /// The same failure, followed by *more* failures of the same rule, after
    /// any it already has ([`DeployError::more`]).
    #[must_use]
    pub fn with_more(mut self, more: impl IntoIterator<Item = DeployFailure>) -> Self {
        self.more.extend(more);
        self
    }

    /// The same failure, after the deploy did *partial*
    /// ([`DeployError::partial`]): nothing is kept when it carries no id,
    /// warning or event.
    #[must_use]
    pub fn with_partial(mut self, partial: DeployOutcome) -> Self {
        let empty =
            partial.remote_id.is_none() && partial.warnings.is_empty() && partial.events.is_empty();
        self.partial = (!empty).then(|| Box::new(partial));
        self
    }

    /// Whether the run was interrupted.
    pub fn is_interrupted(&self) -> bool {
        matches!(self.connector.as_deref(), Some(ConnectorError::Cancelled))
    }

    /// The connector error this failure came from; one a [`Deployer`] built
    /// itself is the tenant's refusal, with its message and `detail` field.
    pub fn into_connector(self) -> ConnectorError {
        if let Some(error) = self.connector {
            return *error;
        }
        let field = |key: &str| self.failure.field(key).unwrap_or_default().to_owned();
        ConnectorError::Refused {
            platform: field("platform"),
            tenant: field("tenant"),
            detail: self.failure.field("detail").map(str::to_owned),
            message: self.failure.message,
        }
    }
}

/// A [`Deployer`]'s future from one whose failures are connector errors,
/// each converted as [`DeployError::from`] does.
pub fn deploying<'a>(
    future: impl Future<Output = Result<DeployOutcome, ConnectorError>> + Send + 'a,
) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
    Box::pin(async move { future.await.map_err(DeployError::from) })
}

/// [`deploying`] for `request`: a failure that is the request's recreate
/// refusal keeps the refusal's code ([`DeployRequest::refused_recreate`]).
pub fn deploying_for<'a>(
    request: &'a DeployRequest,
    future: impl Future<Output = Result<DeployOutcome, ConnectorError>> + Send + 'a,
) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
    Box::pin(async move {
        future
            .await
            .map_err(|error| request.refused_recreate(DeployError::from(error)))
    })
}

impl From<ConnectorError> for DeployError {
    /// A connector error as a deploy's failure. An answer the tenant
    /// refused or could not give for this rule fails the rule; anything
    /// else (the connection, the credentials, the setup, an interrupt)
    /// fails the tenant.
    fn from(error: ConnectorError) -> Self {
        let (code, scope) = deploy_code(&error);
        let status = match &error {
            ConnectorError::Gateway { status, .. } => Some(*status),
            _ => None,
        };
        Self {
            scope,
            failure: DeployFailure {
                code,
                message: error.to_string(),
                status,
                fields: located(&error),
            },
            connector: Some(Box::new(error)),
            partial: None,
            more: Vec::new(),
        }
    }
}

/// A connector error's code (the facade's) and what it stops in a deploy.
fn deploy_code(error: &ConnectorError) -> (&'static str, DeployScope) {
    use DeployScope::{Rule, Tenant};
    match error {
        ConnectorError::Unreachable { .. } => ("tenant_unreachable", Tenant),
        ConnectorError::Timeout { .. } => ("tenant_timeout", Tenant),
        ConnectorError::Answer { .. } => ("tenant_answer_invalid", Rule),
        ConnectorError::Setup { .. } => ("tenant_setup_invalid", Tenant),
        ConnectorError::MissingCredential { .. } => ("credential_unset", Tenant),
        ConnectorError::Crashed { .. } => ("connector_crashed", Tenant),
        ConnectorError::Refused { .. } => ("tenant_refused", Rule),
        ConnectorError::Authentication { .. } => ("authentication_failed", Tenant),
        ConnectorError::QueryTimedOut { .. } => ("query_timed_out", Rule),
        ConnectorError::Gateway { .. } => ("tenant_gateway", Tenant),
        ConnectorError::Cancelled => ("interrupted", Tenant),
        ConnectorError::NetworkUnavailable { .. } => ("network_unavailable", Tenant),
    }
}

/// What locates a connector error: its platform, tenant, and the address,
/// variable or vendor's detail it names (each only when not empty).
fn located(error: &ConnectorError) -> Vec<(String, String)> {
    let (platform, tenant, more): (&str, &str, Option<(&str, &str)>) = match error {
        ConnectorError::Unreachable {
            platform,
            tenant,
            address,
            ..
        }
        | ConnectorError::Answer {
            platform,
            tenant,
            address,
            ..
        }
        | ConnectorError::Timeout {
            platform,
            tenant,
            address,
            ..
        } => (platform, tenant, Some(("address", address))),
        ConnectorError::MissingCredential {
            platform,
            tenant,
            variable,
            ..
        } => (platform, tenant, Some(("variable", variable))),
        ConnectorError::Refused {
            platform,
            tenant,
            detail,
            ..
        }
        | ConnectorError::Authentication {
            platform,
            tenant,
            detail,
            ..
        }
        | ConnectorError::QueryTimedOut {
            platform,
            tenant,
            detail,
            ..
        } => (
            platform,
            tenant,
            detail.as_deref().map(|detail| ("detail", detail)),
        ),
        ConnectorError::Setup {
            platform, tenant, ..
        }
        | ConnectorError::Crashed {
            platform, tenant, ..
        }
        | ConnectorError::Gateway {
            platform, tenant, ..
        }
        | ConnectorError::NetworkUnavailable { platform, tenant } => (platform, tenant, None),
        ConnectorError::Cancelled => ("", "", None),
    };
    [("platform", platform), ("tenant", tenant)]
        .into_iter()
        .chain(more)
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

/// Rows returned when the caller names no limit (`query.models.DEFAULT_LIMIT`).
pub const DEFAULT_LIMIT: usize = 100;
/// The most rows one query returns per tenant: `opentide query --limit` and
/// the SDKs take 1 to this.
pub const MAX_QUERY_LIMIT: usize = 5_000;
/// How long an asynchronous search may run when the caller names no timeout
/// (`query.models.DEFAULT_TIMEOUT`).
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(120);

/// A UTC interval, `start` inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeWindow {
    /// Where it starts.
    pub start: jiff::Timestamp,
    /// Where it ends.
    pub end: jiff::Timestamp,
}

impl TimeWindow {
    /// *at* as `format_utc_z` writes it: UTC, milliseconds (truncated), `Z`
    /// (`2026-10-26T08:00:00.000Z`).
    pub fn utc_z(at: jiff::Timestamp) -> String {
        let civil = jiff::tz::Offset::UTC.to_datetime(at);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            civil.year(),
            civil.month(),
            civil.day(),
            civil.hour(),
            civil.minute(),
            civil.second(),
            civil.subsec_nanosecond() / 1_000_000
        )
    }

    /// The window's length in whole seconds, at least one (`seconds`).
    pub fn seconds(&self) -> i64 {
        let span = self.end.as_second() - self.start.as_second();
        let nanos = self.end.subsec_nanosecond() - self.start.subsec_nanosecond();
        // `int(total_seconds())` truncates toward zero.
        let whole = if nanos < 0 && span > 0 {
            span - 1
        } else if nanos > 0 && span < 0 {
            span + 1
        } else {
            span
        };
        whole.max(1)
    }

    /// The minute before *now* (`check_window`): `validate query --live`'s.
    pub fn check(now: jiff::Timestamp) -> Self {
        let start = now
            .checked_sub(jiff::SignedDuration::from_secs(60))
            .unwrap_or(now);
        Self { start, end: now }
    }
}

/// *at* as `format_utc_z` writes it ([`TimeWindow::utc_z`]).
pub fn utc_z(at: jiff::Timestamp) -> String {
    TimeWindow::utc_z(at)
}

/// One query to run or check on one tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryRequest {
    /// The query text.
    pub text: String,
    /// Its language (`kql`, `esql`, `cql`, `telemetry`); empty takes the
    /// platform's first (Elastic's `esql`).
    pub language: String,
    /// The time the search covers.
    pub window: TimeWindow,
    /// The most rows to return; a runner asks for one more, to tell a cut.
    pub limit: usize,
    /// Elastic indices, the HarfangLab telemetry source, the CrowdStrike
    /// repository (`--index`).
    pub index: Vec<String>,
    /// Elastic's data view, when a rule names one instead of indices.
    pub data_view: Option<String>,
    /// How long an asynchronous search may run (`--timeout`).
    pub timeout: Duration,
}

impl QueryRequest {
    /// A request for *text* in *language* over *window*, with the defaults
    /// (`DEFAULT_LIMIT` rows, `DEFAULT_TIMEOUT`, no index).
    pub fn new(text: impl Into<String>, language: impl Into<String>, window: TimeWindow) -> Self {
        Self {
            text: text.into(),
            language: language.into(),
            window,
            limit: DEFAULT_LIMIT,
            index: Vec::new(),
            data_view: None,
            timeout: DEFAULT_QUERY_TIMEOUT,
        }
    }

    /// The same request for one row: a live check's (`QueryRunner.check`).
    #[must_use]
    pub fn for_check(&self) -> Self {
        Self {
            limit: 1,
            ..self.clone()
        }
    }
}

/// A column of a query's rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryColumn {
    /// Its name (`process.name`).
    pub name: String,
    /// The vendor's type name, verbatim; `None` when the platform names none.
    pub kind: Option<String>,
}

impl QueryColumn {
    /// A column without a type.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: None,
        }
    }
}

/// One row: its columns in the order they came (`opentide_compile`'s
/// ordered JSON, since serde_json's map sorts its keys).
pub type Row = opentide_compile::json::Object;

/// What a query returned.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct QueryOutcome {
    /// The columns, in order.
    pub columns: Vec<QueryColumn>,
    /// The rows, at most the request's limit.
    pub rows: Vec<Row>,
    /// More rows matched than the limit let through.
    pub truncated: bool,
    /// The platform stopped early and says the rows are incomplete.
    pub partial: bool,
    /// The platform's reservations about the result.
    pub warnings: Vec<String>,
    /// The platform's id of the search (CrowdStrike's job id).
    pub vendor_query_id: Option<String>,
    /// What was sent, when the runner changed the query (a `head` it added).
    pub sent: Option<String>,
    /// The language the runner used.
    pub language: Option<String>,
}

/// Nested objects as dotted keys (`process.name`), in order; lists and empty
/// objects stay values (`query.models.flatten`).
pub fn flatten(document: &Row) -> Row {
    fn into(flat: &mut Row, document: &Row, prefix: &str) {
        for (key, value) in document {
            let name = format!("{prefix}{key}");
            match value {
                opentide_compile::Json::Object(inner) if !inner.is_empty() => {
                    into(flat, inner, &format!("{name}."));
                }
                _ => {
                    flat.insert(name, value.clone());
                }
            }
        }
    }
    let mut flat = Row::new();
    into(&mut flat, document, "");
    flat
}

/// The union of the rows' keys, in first-seen order, for a platform that
/// names no schema (`query.models.columns_of`).
pub fn columns_of(rows: &[Row]) -> Vec<QueryColumn> {
    let mut seen = std::collections::BTreeSet::new();
    rows.iter()
        .flat_map(|row| row.keys())
        .filter(|name| seen.insert(name.as_str()))
        .map(|name| QueryColumn {
            name: name.clone(),
            kind: None,
        })
        .collect()
}

/// *query* with its `//` comments and string literals blanked
/// (`query.runner.kql_code`): opentide-schema's, which the offline Defender
/// checks read too (#1885).
pub use opentide_schema::objects::platform::microsoft_defender::required_columns::kql_code;

/// *query* with `| take limit+1` on a line of its own, unless it already
/// ends in `take` or `limit` (`query.runner.kql_with_limit`).
pub fn kql_with_limit(query: &str, limit: usize) -> String {
    static TAIL: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    let text = query.trim_end().trim_end_matches(';').trim_end();
    let ends_in_take = TAIL
        .get_or_init(|| regex::Regex::new(r"(?i)\|\s*(?:take|limit)\s+\d+\s*$").ok())
        .as_ref()
        .is_some_and(|tail| tail.is_match(kql_code(text).trim_end()));
    if ends_in_take {
        return text.to_owned();
    }
    format!("{text}\n| take {}", limit.saturating_add(1))
}

/// What a live check learns from a tenant that accepted a query, with what
/// the platform's validator's `inspect` adds. A refusal is an error instead: [`ConnectorError::Refused`], or
/// [`ConnectorError::QueryTimedOut`] for a search that outlived the check
/// timeout.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct LiveCheck {
    /// The search's answer, when the check ran one (Defender's required
    /// columns are read from its columns).
    pub result: Option<QueryOutcome>,
    /// Why validation fails the query although the tenant accepted it
    /// (`LiveQueryValidator.inspect`: Defender's custom-detection columns).
    pub errors: Vec<String>,
    /// The tenant's reservations about the verdict.
    pub warnings: Vec<String>,
}

/// Deploys rules.
pub trait Deployer: Send + Sync {
    /// Makes the tenant ready, once, before its first rule: resolves the
    /// credentials and settings a deploy reads, and signs in where the
    /// platform has a sign-in of its own. It sends nothing but that sign-in,
    /// which the first [`deploy`](Self::deploy) then reuses, so a deploy's
    /// requests are the same with or without it. A failure here is the
    /// tenant's, before any rule was sent: `opentide deploy` reports each of
    /// its rules `not attempted` (#1701). By default, nothing to resolve.
    ///
    /// # Errors
    ///
    /// A [`DeployError`] of scope [`DeployScope::Tenant`]: a credential's
    /// variable unset ([`ConnectorError::MissingCredential`]), a setup value
    /// that cannot be used, a sign-in refused or never answered.
    fn open<'a>(&'a self, cx: TenantContext<'a>) -> BoxFuture<'a, Result<(), DeployError>> {
        let _ = cx;
        Box::pin(async { Ok(()) })
    }

    /// Applies *request* to the tenant.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>>;
}

/// [`Deployer::open`]'s future from a resolution whose failures are connector
/// errors: each the tenant's ([`DeployScope::Tenant`]), whatever its kind.
pub fn opening<'a>(
    future: impl Future<Output = Result<(), ConnectorError>> + Send + 'a,
) -> BoxFuture<'a, Result<(), DeployError>> {
    Box::pin(async move {
        future.await.map_err(|error| {
            let mut failed = DeployError::from(error);
            failed.scope = DeployScope::Tenant;
            failed
        })
    })
}

/// Reaches a tenant and writes nothing (`opentide doctor --live`, #1658).
///
/// The check opens the tenant as a deploy does ([`Deployer::open`]: the
/// credentials resolved, the sign-in made where the platform has one), then
/// sends **one** cheap read-only request that needs the credentials, and
/// fails when the tenant refuses it or does not answer. A platform with no
/// such request has no `Prober` ([`Platform::prober`]), never a faked pass.
pub trait Prober: Send + Sync {
    /// Opens the tenant, then makes the platform's one read-only request.
    ///
    /// # Errors
    ///
    /// A [`DeployError`] whose `failure.code` says why: `credential_unset`,
    /// `tenant_setup_invalid`, `tenant_unreachable`, `tenant_timeout`,
    /// `authentication_failed` (the sign-in or the read refused the
    /// credentials), `tenant_refused` (any other non-2xx answer),
    /// `tenant_gateway`.
    fn probe<'a>(&'a self, cx: TenantContext<'a>) -> BoxFuture<'a, Result<(), DeployError>>;
}

/// The `failure.code` of a probe that found the tenant has **no credentials
/// anywhere** (Google SecOps with no `credentials` key and no Application
/// Default Credentials source): the user holds none, so `doctor --live`
/// skips the tenant instead of failing it. Never a deploy's code.
pub const CREDENTIALS_UNAVAILABLE: &str = "credentials_unavailable";

/// [`Prober::probe`]'s future from one whose failures are connector errors,
/// each the tenant's ([`DeployScope::Tenant`]).
pub fn probing<'a>(
    future: impl Future<Output = Result<(), ConnectorError>> + Send + 'a,
) -> BoxFuture<'a, Result<(), DeployError>> {
    opening(future)
}

/// The verdict of a probe's read-only request on the answer's *status*: a
/// 2xx is the tenant reached; 401 and 403 are the credentials refused
/// ([`ConnectorError::Authentication`]); any other status is a refusal
/// ([`ConnectorError::Refused`]) naming it. *what* says the request in words
/// (`reading the policies`); neither it nor the message holds a credential
/// or the answer's body.
///
/// # Errors
///
/// As above.
pub fn probe_verdict(
    platform: &str,
    tenant: &str,
    what: &str,
    status: u16,
) -> Result<(), ConnectorError> {
    match status {
        200..=299 => Ok(()),
        401 | 403 => Err(ConnectorError::authentication(
            platform,
            tenant,
            format!("{platform} tenant '{tenant}' refused the credentials ({what}): HTTP {status}"),
        )),
        _ => Err(ConnectorError::refused(
            platform,
            tenant,
            format!("{platform} tenant '{tenant}' answered HTTP {status} ({what})"),
            None,
        )),
    }
}

/// Checks queries on the tenant (`validate query --live`).
pub trait LiveValidator: Send + Sync {
    /// Checks *request* (`QueryRunner.check`, then the validator's
    /// `inspect`): by default a search for one row over its window, which
    /// the caller sets to the minute before now ([`TimeWindow::check`]).
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>>;
}

/// Runs queries (`opentide query`). Saves nothing on the tenant.
pub trait QueryRunner: Send + Sync {
    /// Runs *request*. A search the runner stops waiting for (cancellation)
    /// is stopped on the tenant where the API allows it (CrowdStrike).
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>>;
}

/// Shares objects (MISP).
pub trait Sharer: Send + Sync {
    /// Shares *object*, returning the remote identifier.
    fn share<'a>(
        &'a self,
        cx: TenantContext<'a>,
        object: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<Option<String>, ConnectorError>>;
}

/// Moves deployment state between formats with what the tenant knows
/// (`deploy migrate-state`).
pub trait StateMigrator: Send + Sync {
    /// The tenant's identifier of each rule named in *rule_ids*, in order.
    fn lookup<'a>(
        &'a self,
        cx: TenantContext<'a>,
        rule_ids: &'a [String],
    ) -> BoxFuture<'a, Result<Vec<Option<String>>, ConnectorError>>;
}

/// One finding of a platform's own check of a rule's configuration block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationFinding {
    /// Where, inside the block: keys and list indexes as strings.
    pub path: Vec<String>,
    /// One sentence.
    pub message: String,
    /// A warning rather than an error.
    pub warning: bool,
}

/// Checks a rule's `configurations.<platform>` block with the platform's own
/// model: a plugin's (its Python model), since the built-in blocks are the
/// schema's.
pub trait ConfigurationCheck: Send + Sync {
    /// The findings of *block*, the block as JSON; an error when the check
    /// itself could not run.
    fn check(&self, block: &serde_json::Value)
    -> Result<Vec<ConfigurationFinding>, ConnectorError>;
}

/// A platform and what it can do.
pub trait Platform: Send + Sync {
    /// Its identifier (`sentinel`, `elastic`, a plugin's entry-point name).
    fn id(&self) -> &str;
    /// Its deployer.
    fn deployer(&self) -> Option<&dyn Deployer> {
        None
    }
    /// Its connectivity check (`opentide doctor --live`); `None` where no
    /// read-only request can show the credentials work.
    fn prober(&self) -> Option<&dyn Prober> {
        None
    }
    /// Its live validator; `None` where the API cannot check a query
    /// (`supported: False`, never a faked validation).
    fn live_validator(&self) -> Option<&dyn LiveValidator> {
        None
    }
    /// Its query runner.
    fn query_runner(&self) -> Option<&dyn QueryRunner> {
        None
    }
    /// Its sharer.
    fn sharer(&self) -> Option<&dyn Sharer> {
        None
    }
    /// Its state migrator.
    fn state_migrator(&self) -> Option<&dyn StateMigrator> {
        None
    }
    /// Its check of a rule's configuration block; `None` for a built-in
    /// platform, whose block the schema checks.
    fn configuration_check(&self) -> Option<&dyn ConfigurationCheck> {
        None
    }
    /// Whether it is a plugin (an `opentide.platforms` entry point), not one
    /// of the built-in platforms.
    fn is_plugin(&self) -> bool {
        false
    }
}

/// The platforms a run knows: the built-in ones, then any registered.
#[derive(Default)]
pub struct Registry {
    platforms: Vec<Box<dyn Platform>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.platforms.iter().map(|platform| platform.id()))
            .finish()
    }
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds *platform*. A second platform with an identifier already
    /// registered is refused: a plugin cannot replace a built-in platform.
    pub fn register(&mut self, platform: Box<dyn Platform>) -> Result<(), String> {
        if self.get(platform.id()).is_some() {
            return Err(format!("platform {} is already registered", platform.id()));
        }
        self.platforms.push(platform);
        Ok(())
    }

    /// The platform *id*.
    pub fn get(&self, id: &str) -> Option<&dyn Platform> {
        self.platforms
            .iter()
            .find(|platform| platform.id() == id)
            .map(AsRef::as_ref)
    }

    /// Every platform's identifier, in registration order.
    pub fn ids(&self) -> Vec<&str> {
        self.platforms
            .iter()
            .map(|platform| platform.id())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectorError, DeployError, DeployEvent, DeployFailure, DeployOutcome, DeployRequest,
        DeployScope, DeployWarning, Operation, kql_code, kql_with_limit,
    };

    #[test]
    fn a_connector_error_fails_the_rule_or_the_tenant() {
        let refused: DeployError =
            ConnectorError::refused("splunk", "soc", "HTTP 400 for the rule", Some("bad".into()))
                .into();
        assert_eq!(refused.scope, DeployScope::Rule);
        assert_eq!(refused.failure.code, "tenant_refused");
        assert_eq!(refused.failure.message, "HTTP 400 for the rule");
        assert_eq!(
            refused.failure.fields,
            [("platform", "splunk"), ("tenant", "soc"), ("detail", "bad")]
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
        );
        let gateway: DeployError = ConnectorError::Gateway {
            platform: "splunk".into(),
            tenant: "soc".into(),
            message: "HTML from the proxy".into(),
            status: 502,
        }
        .into();
        assert_eq!(gateway.scope, DeployScope::Tenant);
        assert_eq!(
            (gateway.failure.code, gateway.failure.status),
            ("tenant_gateway", Some(502))
        );
        let unset: DeployError = ConnectorError::MissingCredential {
            platform: "splunk".into(),
            tenant: "soc".into(),
            key: "token".into(),
            variable: "SPLUNK_TOKEN".into(),
        }
        .into();
        assert_eq!(unset.scope, DeployScope::Tenant);
        assert_eq!(unset.failure.field("variable"), Some("SPLUNK_TOKEN"));
        let interrupted: DeployError = ConnectorError::Cancelled.into();
        assert!(interrupted.is_interrupted());
        assert_eq!(interrupted.failure.fields, Vec::new());
        assert!(matches!(
            interrupted.into_connector(),
            ConnectorError::Cancelled
        ));
    }

    #[test]
    fn a_request_runs_at_its_clock_or_now() {
        let fixed = jiff::Timestamp::from_second(1_700_000_000).unwrap();
        assert_eq!(DeployRequest::delete("r").at(fixed).time(), fixed);
        let before = jiff::Timestamp::now();
        assert!(DeployRequest::delete("r").time() >= before);
    }

    #[test]
    fn a_failure_keeps_what_the_deploy_did_before_it() {
        let created = DeployOutcome::new(Some("43".into()), Operation::Create).with_events(vec![
            DeployEvent::new("sysdig_rule_created").with_field("rule_id", "43"),
        ]);
        let failed = DeployError::from(ConnectorError::refused("sysdig", "soc", "HTTP 409", None))
            .with_partial(created.clone());
        assert_eq!(failed.partial.as_deref(), Some(&created));
        // Nothing to keep is no partial.
        let nothing = DeployError::rule(DeployFailure::new("x", "y"))
            .with_partial(DeployOutcome::new(None, Operation::Update));
        assert_eq!(nothing.partial, None);
        // A recreate refusal keeps what was done before it.
        let recreated =
            DeployOutcome::new(None, Operation::Update).with_warnings(vec![DeployWarning::new(
                "sysdig_rule_missing",
                "the rule was not found",
            )]);
        let request = DeployRequest::new("7", Operation::Update, b"{}".to_vec())
            .refusing_recreate(DeployFailure::new("deployment_state_ignored", "kept out"));
        let refused = request.refused_recreate(
            DeployError::from(ConnectorError::refused("sysdig", "soc", "kept out", None))
                .with_partial(recreated.clone()),
        );
        assert_eq!(refused.failure.code, "deployment_state_ignored");
        assert_eq!(refused.partial.as_deref(), Some(&recreated));
        // The rule's further failures follow the first, through a refusal too.
        let more = vec![DeployFailure::new(
            "google_secops_deployment_failed",
            "HTTP 500",
        )];
        let twice = request.refused_recreate(
            DeployError::from(ConnectorError::refused("sysdig", "soc", "kept out", None))
                .with_more(more.clone()),
        );
        assert_eq!(twice.more, more);
    }

    #[test]
    fn a_recreate_refusal_keeps_its_code_and_only_its_own() {
        let refusal =
            DeployFailure::new("deployment_state_unpersisted", "the new id would be lost");
        let request = DeployRequest::delete("r").refusing_recreate(refusal.clone());
        let refused = request.refused_recreate(
            ConnectorError::refused("sysdig", "soc", "the new id would be lost", None).into(),
        );
        assert_eq!(refused.scope, DeployScope::Rule);
        assert_eq!(refused.failure.code, "deployment_state_unpersisted");
        assert_eq!(refused.failure.field("tenant"), Some("soc"));
        let other = request
            .refused_recreate(ConnectorError::refused("sysdig", "soc", "HTTP 400", None).into());
        assert_eq!(other.failure.code, "tenant_refused");
        // After its code, as Exabeam and Google SecOps refuse it.
        let coded = request.refused_recreate(
            ConnectorError::refused(
                "exabeam",
                "soc",
                "exabeam_x: the new id would be lost",
                None,
            )
            .into(),
        );
        assert_eq!(coded.failure.code, "deployment_state_unpersisted");
        // A tenant's failure is never the rule's refusal, nor does an empty one match.
        let unreachable = request.refused_recreate(
            ConnectorError::Setup {
                platform: "sysdig".into(),
                tenant: "soc".into(),
                message: "the new id would be lost".into(),
            }
            .into(),
        );
        assert_eq!(unreachable.scope, DeployScope::Tenant);
        let empty = DeployRequest::delete("r")
            .refusing_recreate(DeployFailure::new("deployment_state_unpersisted", ""));
        let kept = empty.refused_recreate(ConnectorError::refused("s", "t", "", None).into());
        assert_eq!(kept.failure.code, "tenant_refused");
    }

    #[test]
    fn a_deployers_own_failure_reads_back_as_a_refusal() {
        let error = DeployError::rule(
            DeployFailure::new("sentinel_one_rule_not_found", "no such rule")
                .with_status(404)
                .with_field("platform", "sentinel_one")
                .with_field("tenant", "soc")
                .with_field("detail", "Rule 7 not found"),
        );
        assert_eq!(error.to_string(), "no such rule");
        assert!(!error.is_interrupted());
        let ConnectorError::Refused {
            platform,
            tenant,
            message,
            detail,
        } = error.into_connector()
        else {
            panic!("not a refusal");
        };
        assert_eq!(
            (
                platform.as_str(),
                tenant.as_str(),
                message.as_str(),
                detail.as_deref()
            ),
            (
                "sentinel_one",
                "soc",
                "no such rule",
                Some("Rule 7 not found")
            )
        );
    }

    #[test]
    fn a_doubled_quote_stays_inside_a_verbatim_string() {
        assert_eq!(
            kql_code(r#"x @"a""b\" y"#),
            format!("x @{} y", " ".repeat(7))
        );
        assert_eq!(
            kql_with_limit(r#"T | where x == @"a""b\" | take 3"#, 10),
            r#"T | where x == @"a""b\" | take 3"#
        );
    }

    #[test]
    fn multi_line_strings_are_blanked_up_to_the_same_chord() {
        assert_eq!(
            kql_code("a ```b//\n~~~c``` d"),
            format!("a {} d", " ".repeat(14))
        );
        assert_eq!(
            kql_code("a ~~~b```c~~~ d"),
            format!("a {} d", " ".repeat(11))
        );
        assert_eq!(kql_code("a ```b"), format!("a {}", " ".repeat(4)));
        assert_eq!(
            kql_with_limit("T | where x == ```| take 3```", 10),
            "T | where x == ```| take 3```\n| take 11"
        );
    }

    #[test]
    fn a_block_comment_is_code() {
        // Kusto's comments are `//` only (the Kusto grammar's `KqlTokens.g4`).
        assert_eq!(kql_code("/* T */ U"), "/* T */ U");
    }
}
