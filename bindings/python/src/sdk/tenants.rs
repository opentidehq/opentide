//! The facade's tenant operations (feature `connectors`; UC-5.2b, #837):
//! [`TenantConfig`], [`Connection`] and [`Canceller`], one to one.
//!
//! `Connection.open` is synchronous, as the facade's is: it resolves the
//! tenant's credentials and builds its client, and sends nothing. `query`,
//! `validate_query` and `deploy` are the facade's `async fn`s: each returns
//! an awaitable ([`Pending`]) that runs the operation on a tokio runtime
//! (pyo3-async-runtimes', started on the first operation) without the GIL,
//! and resolves to its document as JSON text. Cancelling the awaitable drops
//! the operation, which stops a search on the tenant where the API allows it.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use opentide::connectors::{
    self, ConnectOptions, DEFAULT_LIMIT, DEFAULT_QUERY_TIMEOUT, DeployOutcome, DeployRequest,
    LiveCheck, Operation, QueryOutcome, QueryRequest, RUNTIME_UNAVAILABLE, TimeWindow, Timestamp,
};
use pyo3::prelude::*;
use serde::Serialize;

use super::{failure, from_facade, to_json};

/// An option's value the facade cannot take: `usage_invalid_value`.
fn invalid(message: String) -> PyErr {
    failure("usage_invalid_value", message)
}

/// A tenant as the workspace configures it, or as code configures it: its
/// platform, its name and its `setup` (`$NAME` credentials unresolved).
#[pyclass(frozen, module = "opentide._native.sdk")]
pub struct TenantConfig {
    inner: connectors::TenantConfig,
}

impl From<connectors::TenantConfig> for TenantConfig {
    fn from(inner: connectors::TenantConfig) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl TenantConfig {
    /// The tenant *name* of *platform* with its *setup*: each key and its
    /// value, a `$NAME` value read from the environment when it connects.
    #[new]
    fn new(platform: String, name: String, setup: Vec<(String, String)>) -> Self {
        Self {
            inner: connectors::TenantConfig::new(platform, name, setup),
        }
    }

    /// The platform's identifier (`splunk`, `sentinel_one`).
    #[getter]
    fn platform(&self) -> String {
        self.inner.platform().to_owned()
    }

    /// The tenant's name.
    #[getter]
    fn name(&self) -> String {
        self.inner.name().to_owned()
    }

    /// The keys of its `setup`, in name order; never their values.
    #[getter]
    fn setup_keys(&self) -> Vec<String> {
        self.inner.setup_keys().map(str::to_owned).collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "TenantConfig({:?}, {:?})",
            self.inner.platform(),
            self.inner.name()
        )
    }
}

/// The platforms with a connector, in the order opentide lists them.
#[pyfunction]
pub fn platforms() -> Vec<&'static str> {
    connectors::platforms()
}

/// What the connector of *platform* can do, `(deploy, live_validation,
/// query)`; `None` for a platform without one.
#[pyfunction]
pub fn capabilities(platform: &str) -> Option<(bool, bool, bool)> {
    connectors::capabilities(platform).map(flags)
}

fn flags(capabilities: connectors::Capabilities) -> (bool, bool, bool) {
    (
        capabilities.deploy,
        capabilities.live_validation,
        capabilities.query,
    )
}

/// Cancels a connection's operations: the one running stops with the code
/// `interrupted`, and so does every later one.
#[pyclass(frozen, module = "opentide._native.sdk")]
pub struct Canceller {
    inner: connectors::Canceller,
}

#[pymethods]
impl Canceller {
    /// Cancels.
    fn cancel(&self) {
        self.inner.cancel();
    }

    /// Whether `cancel` was called.
    #[getter]
    fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }
}

/// One tenant's client: built from that tenant's own settings, its
/// credentials resolved. Secrets never reach a message or a `repr`.
#[pyclass(frozen, module = "opentide._native.sdk")]
pub struct Connection {
    inner: Arc<connectors::Connection>,
}

#[pymethods]
impl Connection {
    /// Connects to *tenant*: resolves its credentials and builds its client.
    /// Nothing is sent until an operation runs. *environment* replaces the
    /// process's environment for credentials, CA bundles and proxies;
    /// *proxy* comes before the environment's; *timeout* is how long, in
    /// seconds, a tenant may take to answer a read (a query or a query
    /// check): a deploy waits as long as `opentide deploy` does, whatever
    /// *timeout* is.
    #[staticmethod]
    #[pyo3(signature = (tenant, *, environment=None, proxy=None, timeout=None))]
    fn open(
        py: Python<'_>,
        tenant: PyRef<'_, TenantConfig>,
        environment: Option<Vec<(String, String)>>,
        proxy: Option<String>,
        timeout: Option<f64>,
    ) -> PyResult<Self> {
        let mut options = ConnectOptions::default();
        if let Some(vars) = environment {
            options = options.environment(vars);
        }
        if let Some(proxy) = proxy {
            options = options.proxy(proxy);
        }
        if let Some(seconds) = timeout {
            options = options.timeout(duration("timeout", seconds)?);
        }
        let tenant = tenant.inner.clone();
        let inner = py
            .detach(|| connectors::Connection::open(&tenant, &options))
            .map_err(|error| from_facade(&error))?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The platform's identifier.
    #[getter]
    fn platform(&self) -> String {
        self.inner.platform().to_owned()
    }

    /// The tenant's name.
    #[getter]
    fn tenant(&self) -> String {
        self.inner.tenant().to_owned()
    }

    /// What this tenant's connector can do: `(deploy, live_validation,
    /// query)`.
    #[getter]
    fn capabilities(&self) -> (bool, bool, bool) {
        flags(self.inner.capabilities())
    }

    /// A handle that cancels this connection's operations from elsewhere.
    fn canceller(&self) -> Canceller {
        Canceller {
            inner: self.inner.canceller(),
        }
    }

    /// Runs *text* on the tenant (`opentide query`): an awaitable of the
    /// rows' document, `{columns, rows, truncated, partial, warnings,
    /// vendor_query_id, sent, language}`, as JSON. *start* and *end* are
    /// RFC 3339 instants (default: the 24 hours before *end*, which is now by
    /// default), as the Node SDK reads them.
    #[pyo3(signature = (text, language, *, start=None, end=None, limit=DEFAULT_ROWS, index=Vec::new(), data_view=None, timeout=DEFAULT_QUERY_TIMEOUT.as_secs_f64()))]
    #[expect(
        clippy::too_many_arguments,
        reason = "the query request's fields, one keyword each, as the facade has them"
    )]
    fn query<'py>(
        &self,
        py: Python<'py>,
        text: String,
        language: String,
        start: Option<String>,
        end: Option<String>,
        limit: i64,
        index: Vec<String>,
        data_view: Option<String>,
        timeout: f64,
    ) -> PyResult<Pending<'py>> {
        let window = Window {
            start,
            end,
            since: QUERY_SINCE,
        };
        let request = request(text, language, window, limit, index, data_view, timeout)?;
        let connection = Arc::clone(&self.inner);
        pending(py, async move {
            let outcome = connection
                .query(&request)
                .await
                .map_err(|error| from_facade(&error))?;
            to_json(&QueryJson::from(&outcome))
        })
    }

    /// Checks *text* on the tenant (`opentide validate query --live`): an
    /// awaitable of `{result, errors, warnings}`, as JSON. A query the tenant
    /// refuses raises `tenant_refused`; a platform that cannot check a query
    /// live raises `operation_unsupported`.
    #[pyo3(signature = (text, language, *, start=None, end=None, limit=DEFAULT_ROWS, index=Vec::new(), data_view=None, timeout=DEFAULT_QUERY_TIMEOUT.as_secs_f64()))]
    #[expect(
        clippy::too_many_arguments,
        reason = "the query request's fields, one keyword each, as the facade has them"
    )]
    fn validate_query<'py>(
        &self,
        py: Python<'py>,
        text: String,
        language: String,
        start: Option<String>,
        end: Option<String>,
        limit: i64,
        index: Vec<String>,
        data_view: Option<String>,
        timeout: f64,
    ) -> PyResult<Pending<'py>> {
        let window = Window {
            start,
            end,
            since: CHECK_SINCE,
        };
        let request = request(text, language, window, limit, index, data_view, timeout)?;
        let connection = Arc::clone(&self.inner);
        pending(py, async move {
            let check = connection
                .validate_query(&request)
                .await
                .map_err(|error| from_facade(&error))?;
            to_json(&LiveCheckJson::from(&check))
        })
    }

    /// Applies *operation* (`create`, `update`, `disable` or `delete`) to the
    /// rule *rule_id* on the tenant, sending *body* (a deploy plan's
    /// payload) as its bytes: an awaitable of `{remote_id, operation,
    /// warnings}`, as
    /// JSON. *policies* are Sysdig's runtime policies for the rule (a plan
    /// entry's `policies`); `None` takes the tenant's. A `delete` takes no
    /// *body*; the other operations need one (`usage_invalid_value`).
    #[pyo3(signature = (rule_id, operation, body=None, *, policies=None))]
    fn deploy<'py>(
        &self,
        py: Python<'py>,
        rule_id: String,
        operation: &str,
        body: Option<Vec<u8>>,
        policies: Option<Vec<String>>,
    ) -> PyResult<Pending<'py>> {
        let operation = match operation {
            "create" => Operation::Create,
            "update" => Operation::Update,
            "disable" => Operation::Disable,
            "delete" => Operation::Delete,
            other => {
                return Err(super::usage(format!(
                    "operation: `{other}` is not create, update, disable or delete"
                )));
            }
        };
        let request = match body {
            Some(body) => DeployRequest::new(rule_id, operation, body),
            None if operation == Operation::Delete => DeployRequest::delete(rule_id),
            None => {
                return Err(invalid(format!(
                    "body: a {} needs the compiled rule; only a delete takes none",
                    match operation {
                        Operation::Create => "create",
                        Operation::Update => "update",
                        _ => "disable",
                    }
                )));
            }
        }
        .with_policies(policies);
        let connection = Arc::clone(&self.inner);
        pending(py, async move {
            let outcome = connection
                .deploy(&request)
                .await
                .map_err(|error| from_facade(&error))?;
            to_json(&DeployJson::from(&outcome))
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "Connection({:?}, {:?})",
            self.inner.platform(),
            self.inner.tenant()
        )
    }
}

/// An operation in flight: the awaitable pyo3-async-runtimes returns, which
/// resolves to the operation's document as JSON text.
pub struct Pending<'py>(Bound<'py, PyAny>);

impl<'py> IntoPyObject<'py> for Pending<'py> {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = std::convert::Infallible;

    #[cfg(feature = "stubs")]
    const OUTPUT_TYPE: pyo3::inspect::PyStaticExpr = pyo3::type_hint_subscript!(
        pyo3::type_hint_identifier!("collections.abc", "Awaitable"),
        pyo3::type_hint_identifier!("builtins", "str")
    );

    fn into_pyobject(self, _py: Python<'py>) -> Result<Self::Output, Self::Error> {
        Ok(self.0)
    }
}

/// *work* as an awaitable of the running event loop, on the SDK's runtime.
fn pending<F>(py: Python<'_>, work: F) -> PyResult<Pending<'_>>
where
    F: Future<Output = PyResult<String>> + Send + 'static,
{
    runtime()?;
    pyo3_async_runtimes::tokio::future_into_py(py, work).map(Pending)
}

/// Starts the runtime the operations run on, once per process: a failure to
/// start it is `runtime_unavailable`, never a panic.
fn runtime() -> PyResult<()> {
    static READY: OnceLock<Result<(), String>> = OnceLock::new();
    READY
        .get_or_init(|| {
            // The process's one runtime (#1558), never dropped.
            let runtime = opentide::connectors::runtime().map_err(|error| error.to_string())?;
            pyo3_async_runtimes::tokio::init_with_runtime(runtime)
                .map_err(|()| "the network runtime was already started elsewhere".to_owned())
        })
        .clone()
        .map_err(|message| failure(RUNTIME_UNAVAILABLE, message))
}

fn duration(name: &str, seconds: f64) -> PyResult<Duration> {
    Duration::try_from_secs_f64(seconds)
        .map_err(|_| invalid(format!("{name}: {seconds} is not a number of seconds")))
}

fn instant(name: &str, text: &str) -> PyResult<Timestamp> {
    text.parse().map_err(|error| {
        invalid(format!(
            "{name}: `{text}` is not an RFC 3339 instant: {error}"
        ))
    })
}

/// The facade's request; a missing *end* is now, a missing *start*
/// `window.since` before *end* (a day for a query, a minute for a live
/// check); a negative *limit* is refused here, one above
/// [`connectors::MAX_QUERY_LIMIT`] by the facade.
fn request(
    text: String,
    language: String,
    window: Window,
    limit: i64,
    index: Vec<String>,
    data_view: Option<String>,
    timeout: f64,
) -> PyResult<QueryRequest> {
    let end = match window.end {
        Some(end) => instant("end", &end)?,
        None => Timestamp::now(),
    };
    let mut span = TimeWindow::check(end);
    span.start = end.checked_sub(window.since).unwrap_or(span.start);
    if let Some(start) = window.start {
        span.start = instant("start", &start)?;
    }
    let window = span;
    if window.start > window.end {
        return Err(invalid("start: the window starts after it ends".to_owned()));
    }
    let mut request = QueryRequest::new(text, language, window);
    // The facade refuses a limit outside 1 to MAX_QUERY_LIMIT; one that is
    // no row count at all (negative) is refused here, in the same words.
    request.limit = usize::try_from(limit).map_err(|_| {
        invalid(format!(
            "limit must be between 1 and {}, not {limit}",
            connectors::MAX_QUERY_LIMIT
        ))
    })?;
    request.index = index;
    request.data_view = data_view;
    request.timeout = duration("timeout", timeout)?;
    Ok(request)
}

/// A query's window as the caller gave it: RFC 3339 instants, and how far
/// before `end` it starts when `start` is not given.
struct Window {
    start: Option<String>,
    end: Option<String>,
    since: Duration,
}

/// [`DEFAULT_LIMIT`] as the `limit` argument's type, which also reads a
/// negative number so that it is refused in opentide's words.
#[expect(clippy::cast_possible_wrap, reason = "100 fits an i64")]
const DEFAULT_ROWS: i64 = DEFAULT_LIMIT as i64;

/// `query`'s default window: the 24 hours before its end, as `opentide query`
/// and the Node SDK search.
const QUERY_SINCE: Duration = Duration::from_hours(24);
/// A live check's default window: the minute before its end
/// ([`TimeWindow::check`]).
const CHECK_SINCE: Duration = Duration::from_secs(60);

/// A query's document, in this order.
#[derive(Serialize)]
struct QueryJson<'a> {
    columns: Vec<ColumnJson<'a>>,
    rows: &'a [connectors::Row],
    truncated: bool,
    partial: bool,
    warnings: &'a [String],
    vendor_query_id: Option<&'a str>,
    sent: Option<&'a str>,
    language: Option<&'a str>,
}

/// A column: its name and the vendor's type name, `None` when it names none.
#[derive(Serialize)]
struct ColumnJson<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    kind: Option<&'a str>,
}

impl<'a> From<&'a QueryOutcome> for QueryJson<'a> {
    fn from(outcome: &'a QueryOutcome) -> Self {
        Self {
            columns: outcome
                .columns
                .iter()
                .map(|column| ColumnJson {
                    name: &column.name,
                    kind: column.kind.as_deref(),
                })
                .collect(),
            rows: &outcome.rows,
            truncated: outcome.truncated,
            partial: outcome.partial,
            warnings: &outcome.warnings,
            vendor_query_id: outcome.vendor_query_id.as_deref(),
            sent: outcome.sent.as_deref(),
            language: outcome.language.as_deref(),
        }
    }
}

/// A live check's document, in this order.
#[derive(Serialize)]
struct LiveCheckJson<'a> {
    result: Option<QueryJson<'a>>,
    errors: &'a [String],
    warnings: &'a [String],
}

impl<'a> From<&'a LiveCheck> for LiveCheckJson<'a> {
    fn from(check: &'a LiveCheck) -> Self {
        Self {
            result: check.result.as_ref().map(QueryJson::from),
            errors: &check.errors,
            warnings: &check.warnings,
        }
    }
}

/// A deploy's document.
#[derive(Serialize)]
pub(super) struct DeployJson<'a> {
    remote_id: Option<&'a str>,
    operation: &'static str,
    warnings: Vec<DeployWarningJson<'a>>,
    events: Vec<DeployEventJson<'a>>,
}

/// A deploy's warning as `DeployWarning` reads it.
#[derive(Serialize)]
struct DeployWarningJson<'a> {
    code: &'a str,
    message: &'a str,
    raised: bool,
}

/// A deploy's event as `DeployEvent` reads it: its fields as `[key, value]`
/// pairs, in order.
#[derive(Serialize)]
struct DeployEventJson<'a> {
    name: &'a str,
    fields: &'a [(String, String)],
}

impl<'a> From<&'a DeployOutcome> for DeployJson<'a> {
    fn from(outcome: &'a DeployOutcome) -> Self {
        Self {
            remote_id: outcome.remote_id.as_deref(),
            operation: match outcome.operation {
                Operation::Create => "create",
                Operation::Update => "update",
                Operation::Disable => "disable",
                Operation::Delete => "delete",
            },
            warnings: outcome
                .warnings
                .iter()
                .map(|warning| DeployWarningJson {
                    code: &warning.code,
                    message: &warning.message,
                    raised: warning.raised,
                })
                .collect(),
            events: outcome
                .events
                .iter()
                .map(|event| DeployEventJson {
                    name: &event.name,
                    fields: &event.fields,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide::connectors::{DeployEvent, DeployWarning};

    fn window(start: Option<&str>, end: Option<&str>, since: Duration) -> Window {
        Window {
            start: start.map(str::to_owned),
            end: end.map(str::to_owned),
            since,
        }
    }

    #[test]
    fn a_window_defaults_to_the_minute_before_its_end() {
        let at = "2026-11-12T10:00:00Z";
        let request = request(
            "x".into(),
            "s1ql".into(),
            window(None, Some(at), CHECK_SINCE),
            7,
            vec!["logs".into()],
            None,
            5.0,
        )
        .unwrap();
        assert_eq!(request.window.end, at.parse::<Timestamp>().unwrap());
        assert_eq!(request.window.seconds(), 60);
        assert_eq!(request.limit, 7);
        assert_eq!(request.index, ["logs"]);
        assert_eq!(request.timeout, Duration::from_secs(5));

        let request = request_from("2026-11-11T10:00:00+00:00", at).unwrap();
        assert_eq!(request.window.seconds(), 86_400);
        // A query's window: the 24 hours before its end, as the Node SDK's.
        let day = |end| {
            super::request(
                "x".into(),
                String::new(),
                window(None, end, QUERY_SINCE),
                1,
                Vec::new(),
                None,
                1.0,
            )
        };
        assert_eq!(day(Some(at)).unwrap().window.seconds(), 86_400);
        assert_eq!(day(None).unwrap().window.seconds(), 86_400);
    }

    #[test]
    fn a_negative_limit_is_refused() {
        let refused = request(
            "x".into(),
            String::new(),
            window(None, None, QUERY_SINCE),
            -1,
            Vec::new(),
            None,
            1.0,
        );
        assert!(refused.is_err());
    }

    fn request_from(start: &str, end: &str) -> PyResult<QueryRequest> {
        request(
            "x".into(),
            String::new(),
            window(Some(start), Some(end), CHECK_SINCE),
            DEFAULT_ROWS,
            Vec::new(),
            None,
            1.0,
        )
    }

    #[test]
    fn a_window_that_ends_before_it_starts_is_refused() {
        // The errors' codes are checked from Python (tests/test_sdk), where
        // an exception can be read.
        for (start, end) in [
            ("2026-11-12T10:00:01Z", "2026-11-12T10:00:00Z"),
            ("yesterday", "2026-11-12T10:00:00Z"),
            ("2026-11-12T10:00:00Z", "soon"),
        ] {
            assert!(request_from(start, end).is_err(), "{start}..{end}");
        }
    }

    #[test]
    fn a_timeout_is_a_number_of_seconds() {
        assert_eq!(
            duration("timeout", 1.5).ok(),
            Some(Duration::from_millis(1500))
        );
        for seconds in [-1.0, f64::NAN, f64::INFINITY] {
            assert!(duration("timeout", seconds).is_err(), "{seconds}");
        }
    }

    #[test]
    fn documents_keep_their_order() {
        let mut row = connectors::Row::new();
        row.insert("z".into(), connectors::Json::Int(1));
        row.insert("a".into(), connectors::Json::Str("x".into()));
        let outcome = QueryOutcome {
            columns: vec![connectors::QueryColumn::named("z")],
            rows: vec![row],
            truncated: true,
            ..QueryOutcome::default()
        };
        assert_eq!(
            serde_json::to_string(&QueryJson::from(&outcome)).unwrap(),
            r#"{"columns":[{"name":"z","type":null}],"rows":[{"z":1,"a":"x"}],"truncated":true,"partial":false,"warnings":[],"vendor_query_id":null,"sent":null,"language":null}"#
        );
        let check = LiveCheck {
            errors: vec!["missing Timestamp".into()],
            ..LiveCheck::default()
        };
        assert_eq!(
            serde_json::to_string(&LiveCheckJson::from(&check)).unwrap(),
            r#"{"result":null,"errors":["missing Timestamp"],"warnings":[]}"#
        );
        let deployed = DeployOutcome::new(Some("42".into()), Operation::Disable);
        assert_eq!(
            serde_json::to_string(&DeployJson::from(&deployed)).unwrap(),
            r#"{"remote_id":"42","operation":"disable","warnings":[],"events":[]}"#
        );
        let recreated = DeployOutcome::new(Some("43".into()), Operation::Update)
            .with_warnings(vec![
                DeployWarning::new("sysdig_rule_recreated", "creating it again"),
                DeployWarning::new("splunk_alert_deleted", "Rule").unraised(),
            ])
            .with_events(vec![
                DeployEvent::new("sysdig_rule_created")
                    .with_field("uuid", "u1")
                    .with_field("rule_id", "43"),
            ]);
        assert_eq!(
            serde_json::to_string(&DeployJson::from(&recreated)).unwrap(),
            concat!(
                r#"{"remote_id":"43","operation":"update","warnings":["#,
                r#"{"code":"sysdig_rule_recreated","message":"creating it again","raised":true},"#,
                r#"{"code":"splunk_alert_deleted","message":"Rule","raised":false}],"#,
                r#""events":[{"name":"sysdig_rule_created","fields":[["uuid","u1"],["rule_id","43"]]}]}"#
            )
        );
    }
}
