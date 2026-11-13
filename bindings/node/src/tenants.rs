//! The facade's tenant operations (feature `connectors`; UC-5.3b, #838):
//! [`TenantConfig`], [`Connection`] and [`Canceller`], one to one, as the
//! Python SDK has them (UC-5.2b).
//!
//! `Connection.open` is synchronous, as the facade's is: it resolves the
//! tenant's credentials and builds its client, and sends nothing. `query`,
//! `validateQuery` and `deploy` are the facade's `async fn`s: each returns a
//! `Promise` at once and runs the operation on a tokio runtime of this addon,
//! started by the first operation (never when Node loads the addon), so
//! Node's event loop keeps running; the result comes back on Node's thread
//! through the promise's deferred. A failure rejects the promise with an
//! `Error` whose `code` is the facade's code and whose `detail` is the
//! vendor's words, as a synchronous call throws.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use napi::Env;
use napi::bindgen_prelude::{Either, Object, Uint8Array, Unknown};
use napi_derive::napi;
use opentide::connectors::{
    self, DEFAULT_LIMIT, DEFAULT_QUERY_TIMEOUT, DeployRequest, Operation, QueryOutcome,
    QueryRequest, RUNTIME_UNAVAILABLE, TimeWindow, Timestamp,
};
use serde::Serialize;

use crate::{Failure, throw};

/// How far back `query` searches when it is given no `start`: the Python
/// SDK's default (`DEFAULT_SINCE`), 24 hours.
const QUERY_SINCE: Duration = Duration::from_secs(24 * 60 * 60);

/// A tenant as the workspace configures it (`Workspace.tenants`), or as code
/// configures it: its platform, its name and its `setup`, whose `$NAME`
/// credentials are read when it connects. Its setup's values never leave it.
#[napi]
pub struct TenantConfig {
    inner: connectors::TenantConfig,
}

impl From<connectors::TenantConfig> for TenantConfig {
    fn from(inner: connectors::TenantConfig) -> Self {
        Self { inner }
    }
}

#[napi]
impl TenantConfig {
    /// The tenant `name` of `platform` with its `setup`: each key and its
    /// value, a `$NAME` value read from the environment when it connects
    /// (`{ url: 'https://s1.example', api_token: '$S1_API_TOKEN' }`).
    #[napi(constructor)]
    pub fn new(platform: String, name: String, setup: HashMap<String, String>) -> Self {
        Self {
            inner: connectors::TenantConfig::new(platform, name, setup),
        }
    }

    /// The platform's identifier (`splunk`, `sentinel_one`).
    #[napi(getter)]
    pub fn platform(&self) -> String {
        self.inner.platform().to_owned()
    }

    /// The tenant's name.
    #[napi(getter)]
    pub fn name(&self) -> String {
        self.inner.name().to_owned()
    }

    /// The keys of its `setup`, in name order; never their values.
    #[napi(getter)]
    pub fn setup_keys(&self) -> Vec<String> {
        self.inner.setup_keys().map(str::to_owned).collect()
    }
}

/// What a platform's connector can do: `Connection.deploy`,
/// `Connection.validateQuery` (`validate query --live`) and
/// `Connection.query` (`opentide query`).
#[napi(object)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// `Connection.deploy`.
    pub deploy: bool,
    /// `Connection.validateQuery`.
    pub live_validation: bool,
    /// `Connection.query`.
    pub query: bool,
}

impl From<connectors::Capabilities> for Capabilities {
    fn from(capabilities: connectors::Capabilities) -> Self {
        Self {
            deploy: capabilities.deploy,
            live_validation: capabilities.live_validation,
            query: capabilities.query,
        }
    }
}

/// The platforms with a connector, in the order opentide lists them.
#[napi]
pub fn platforms() -> Vec<String> {
    connectors::platforms()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// What the connector of `platform` can do; `null` for a platform without
/// one.
#[napi]
pub fn capabilities(platform: String) -> Option<Capabilities> {
    connectors::capabilities(&platform).map(Capabilities::from)
}

/// How `Connection.open` reaches a tenant.
#[napi(object)]
#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    /// Replaces the process's environment for the tenant's `$NAME`
    /// credentials, its CA bundles (`SSL_CERT_FILE`, ...) and its proxies
    /// (`HTTPS_PROXY`, `NO_PROXY`, ...).
    pub environment: Option<HashMap<String, String>>,
    /// The proxy every request goes through, before the environment's.
    pub proxy: Option<String>,
    /// How long, in seconds, the tenant may take to answer a read (Elastic,
    /// Splunk, Carbon Black Cloud, Sentinel); default 120.
    pub timeout: Option<f64>,
}

/// What `query` and `validateQuery` run: `opentide query`'s options.
#[napi(object)]
#[derive(Debug, Clone, Default)]
pub struct QueryOptions {
    /// The query's language (`kql`, `esql`, `s1ql`); empty or unset takes the
    /// platform's first.
    pub language: Option<String>,
    /// Where the search starts: an RFC 3339 instant (`date.toISOString()`).
    /// Default: 24 hours before `end` for `query`, the minute before `end`
    /// for `validateQuery`.
    pub start: Option<String>,
    /// Where the search ends: an RFC 3339 instant. Default: now.
    pub end: Option<String>,
    /// The most rows to return (default 100); `truncated` says there were
    /// more.
    pub limit: Option<u32>,
    /// The Elastic indices, the HarfangLab telemetry source or the
    /// CrowdStrike repository.
    pub index: Option<Vec<String>>,
    /// Elastic's data view.
    pub data_view: Option<String>,
    /// How long, in seconds, an asynchronous search may run (default 120).
    pub timeout: Option<f64>,
}

/// Cancels a connection's operations: the one running rejects with the code
/// `interrupted`, and so does every later one.
#[napi]
pub struct Canceller {
    inner: connectors::Canceller,
}

#[napi]
impl Canceller {
    /// Cancels.
    #[napi]
    pub fn cancel(&self) {
        self.inner.cancel();
    }

    /// Whether `cancel` was called.
    #[napi(getter)]
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }
}

/// One tenant's client, built from that tenant's own settings (TLS, CA
/// bundle, proxy, timeout, credentials). Secrets never reach a message.
///
/// `query`, `validateQuery` and `deploy` return promises: each operation
/// runs off Node's thread, so one connection serves many at once.
#[napi]
pub struct Connection {
    inner: Arc<connectors::Connection>,
}

#[napi]
impl Connection {
    /// Connects to `tenant`: resolves its credentials and builds its client.
    /// Nothing is sent until an operation runs. Throws `credential_unset`
    /// (naming the variable), `tenant_setup_invalid`,
    /// `operation_unsupported` (a platform without a connector) or
    /// `usage_invalid_value` (a timeout that is not a number of seconds).
    #[napi(factory)]
    pub fn open(
        env: &Env,
        tenant: &TenantConfig,
        options: Option<ConnectOptions>,
    ) -> napi::Result<Self> {
        open(tenant, options).map_err(|failure| throw(*env, failure))
    }

    /// The platform's identifier.
    #[napi(getter)]
    pub fn platform(&self) -> String {
        self.inner.platform().to_owned()
    }

    /// The tenant's name.
    #[napi(getter)]
    pub fn tenant(&self) -> String {
        self.inner.tenant().to_owned()
    }

    /// What this tenant's connector can do.
    #[napi(getter)]
    pub fn capabilities(&self) -> Capabilities {
        self.inner.capabilities().into()
    }

    /// A handle that cancels this connection's operations from elsewhere (a
    /// signal handler, a timer).
    #[napi]
    pub fn canceller(&self) -> Canceller {
        Canceller {
            inner: self.inner.canceller(),
        }
    }

    /// Runs `text` on the tenant (`opentide query`) and resolves to at most
    /// `limit` rows. Nothing is saved on the tenant. Rejects with
    /// `tenant_refused` (the vendor's words in `detail`), `query_timed_out`,
    /// `tenant_unreachable`, `authentication_failed`, `interrupted`,
    /// `operation_unsupported`, ...
    #[napi(ts_return_type = "Promise<QueryResult>")]
    pub fn query<'env>(
        &self,
        env: &'env Env,
        text: String,
        options: Option<QueryOptions>,
    ) -> napi::Result<Object<'env>> {
        let work = request(text, options, Since::Day)
            .map(|request| run_query(Arc::clone(&self.inner), request));
        promise(env, work)
    }

    /// Checks `text` on the tenant (`opentide validate query --live`): by
    /// default a search for one row over the minute before now. Resolves for
    /// a query the tenant accepts; rejects with `tenant_refused` for one it
    /// refuses, and with `operation_unsupported` on a platform that cannot
    /// check a query live (CrowdStrike, HarfangLab, Sysdig).
    #[napi(ts_return_type = "Promise<LiveCheck>")]
    pub fn validate_query<'env>(
        &self,
        env: &'env Env,
        text: String,
        options: Option<QueryOptions>,
    ) -> napi::Result<Object<'env>> {
        let work = request(text, options, Since::Minute)
            .map(|request| run_check(Arc::clone(&self.inner), request));
        promise(env, work)
    }

    /// Applies `operation` to the rule `ruleId` on the tenant, sending `body`
    /// (the request `opentide deploy` compiles for this tenant) as its
    /// bytes, and resolves to the platform's identifier of the rule. Rejects
    /// with `tenant_refused`, the other codes of `query`, and
    /// `operation_unsupported` on a platform whose rules deploy only through
    /// `opentide deploy` (Elastic).
    #[napi(ts_return_type = "Promise<DeployOutcome>")]
    pub fn deploy<'env>(
        &self,
        env: &'env Env,
        rule_id: String,
        #[napi(ts_arg_type = "'create' | 'update' | 'disable' | 'delete'")] operation: String,
        body: Either<String, Uint8Array>,
    ) -> napi::Result<Object<'env>> {
        let body = match body {
            Either::A(text) => text.into_bytes(),
            Either::B(bytes) => bytes.to_vec(),
        };
        let work = deploy_request(rule_id, &operation, body)
            .map(|request| run_deploy(Arc::clone(&self.inner), request));
        promise(env, work)
    }
}

/// A column of a query's rows.
#[napi(
    object,
    object_to_js = false,
    object_from_js = false,
    use_nullable = true
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryColumn {
    /// Its name (`process.name`).
    pub name: String,
    /// The vendor's type name; `null` when the platform names none.
    #[napi(js_name = "type")]
    #[serde(rename = "type")]
    pub kind: Option<String>,
}

/// What `query` resolves to.
#[napi(
    object,
    object_to_js = false,
    object_from_js = false,
    use_nullable = true
)]
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResult {
    /// The columns, in order.
    pub columns: Vec<QueryColumn>,
    /// The rows, at most the request's `limit`: each an object of its
    /// columns in the order they came.
    #[napi(ts_type = "Array<Record<string, any>>")]
    pub rows: Vec<connectors::Row>,
    /// More rows matched than the limit let through.
    pub truncated: bool,
    /// The platform stopped early and says the rows are incomplete.
    pub partial: bool,
    /// The platform's reservations about the result.
    pub warnings: Vec<String>,
    /// The platform's id of the search (CrowdStrike's job id).
    pub vendor_query_id: Option<String>,
    /// What was sent, when the connector changed the query (a limit it
    /// added).
    pub sent: Option<String>,
    /// The language the connector used.
    pub language: Option<String>,
}

impl From<QueryOutcome> for QueryResult {
    fn from(outcome: QueryOutcome) -> Self {
        Self {
            columns: outcome
                .columns
                .into_iter()
                .map(|column| QueryColumn {
                    name: column.name,
                    kind: column.kind,
                })
                .collect(),
            rows: outcome.rows,
            truncated: outcome.truncated,
            partial: outcome.partial,
            warnings: outcome.warnings,
            vendor_query_id: outcome.vendor_query_id,
            sent: outcome.sent,
            language: outcome.language,
        }
    }
}

/// What `validateQuery` resolves to, for a query the tenant accepted.
#[napi(
    object,
    object_to_js = false,
    object_from_js = false,
    use_nullable = true
)]
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LiveCheck {
    /// The search's answer, when the check ran one.
    pub result: Option<QueryResult>,
    /// Why validation still fails the query (Defender's required columns).
    pub errors: Vec<String>,
    /// The tenant's reservations about the verdict.
    pub warnings: Vec<String>,
}

impl From<connectors::LiveCheck> for LiveCheck {
    fn from(check: connectors::LiveCheck) -> Self {
        Self {
            result: check.result.map(QueryResult::from),
            errors: check.errors,
            warnings: check.warnings,
        }
    }
}

/// What `deploy` resolves to.
#[napi(
    object,
    object_to_js = false,
    object_from_js = false,
    use_nullable = true
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployOutcome {
    /// The platform's identifier of the rule, which a deploy keeps in its
    /// deployment state.
    pub remote_id: Option<String>,
    /// What was done.
    #[napi(ts_type = "'create' | 'update' | 'disable' | 'delete'")]
    pub operation: String,
}

impl From<connectors::DeployOutcome> for DeployOutcome {
    fn from(outcome: connectors::DeployOutcome) -> Self {
        Self {
            remote_id: outcome.remote_id,
            operation: operation_name(outcome.operation).to_owned(),
        }
    }
}

/// `Connection.open`'s connection.
fn open(tenant: &TenantConfig, options: Option<ConnectOptions>) -> Result<Connection, Failure> {
    let options = options.unwrap_or_default();
    let mut connect = connectors::ConnectOptions::default();
    if let Some(vars) = options.environment {
        connect = connect.environment(vars);
    }
    if let Some(proxy) = options.proxy {
        connect = connect.proxy(proxy);
    }
    if let Some(seconds) = options.timeout {
        connect = connect.timeout(duration("timeout", seconds)?);
    }
    let inner = connectors::Connection::open(&tenant.inner, &connect)?;
    Ok(Connection {
        inner: Arc::new(inner),
    })
}

async fn run_query(
    connection: Arc<connectors::Connection>,
    request: QueryRequest,
) -> Result<QueryResult, Failure> {
    Ok(connection.query(&request).await?.into())
}

async fn run_check(
    connection: Arc<connectors::Connection>,
    request: QueryRequest,
) -> Result<LiveCheck, Failure> {
    Ok(connection.validate_query(&request).await?.into())
}

async fn run_deploy(
    connection: Arc<connectors::Connection>,
    request: DeployRequest,
) -> Result<DeployOutcome, Failure> {
    Ok(connection.deploy(&request).await?.into())
}

/// What settles a promise, on Node's thread: the document, or the error.
type Resolver = Box<dyn FnOnce(Env) -> napi::Result<Unknown<'static>> + Send>;

/// A promise of `work`'s document: `work` runs on the SDK's runtime and the
/// promise settles on Node's thread. A request that does not convert, or a
/// runtime that does not start, rejects it.
fn promise<T, F>(env: &Env, work: Result<F, Failure>) -> napi::Result<Object<'_>>
where
    T: Serialize + Send + 'static,
    F: Future<Output = Result<T, Failure>> + Send + 'static,
{
    let (deferred, promise) = env.create_deferred::<Unknown<'static>, Resolver>()?;
    // Boxed: the deferred's type, whose document borrows from no `Env`, is
    // then out of sight of the spawned future's `Send` check, which cannot
    // prove a higher-ranked lifetime (rust-lang/rust#110338).
    let settle: Box<dyn FnOnce(Result<T, Failure>) + Send> = Box::new(move |outcome| {
        deferred.resolve(Box::new(move |env| match outcome {
            Ok(document) => env.to_js_value(&document),
            Err(failure) => Err(throw(env, failure)),
        }));
    });
    match work.and_then(|work| Ok((runtime()?, work))) {
        Ok((runtime, work)) => {
            runtime.spawn(async move { settle(work.await) });
        }
        Err(failure) => settle(Err(failure)),
    }
    Ok(promise)
}

/// The runtime the operations run on, started by the first one: a failure
/// to start it is `runtime_unavailable`, never a panic.
fn runtime() -> Result<&'static tokio::runtime::Runtime, Failure> {
    static RUNTIME: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("opentide-sdk")
                .build()
                .map_err(|error| format!("cannot start the network runtime: {error}"))
        })
        .as_ref()
        .map_err(|message| Failure::new(RUNTIME_UNAVAILABLE, message.clone()))
}

/// Where a window without a `start` starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Since {
    /// 24 hours before its end: `query`'s.
    Day,
    /// The minute before its end: a live check's ([`TimeWindow::check`]).
    Minute,
}

/// The facade's request from `options`; a missing `end` is now.
fn request(
    text: String,
    options: Option<QueryOptions>,
    since: Since,
) -> Result<QueryRequest, Failure> {
    let options = options.unwrap_or_default();
    let end = match options.end {
        Some(end) => instant("end", &end)?,
        None => Timestamp::now(),
    };
    let mut window = TimeWindow::check(end);
    if since == Since::Day {
        window.start = end.checked_sub(QUERY_SINCE).unwrap_or(window.start);
    }
    if let Some(start) = options.start {
        window.start = instant("start", &start)?;
    }
    if window.start > window.end {
        return Err(Failure::invalid(
            "start: the window starts after it ends".to_owned(),
        ));
    }
    let mut request = QueryRequest::new(text, options.language.unwrap_or_default(), window);
    request.limit = options.limit.map_or(DEFAULT_LIMIT, |limit| {
        usize::try_from(limit).unwrap_or(usize::MAX)
    });
    request.index = options.index.unwrap_or_default();
    request.data_view = options.data_view;
    request.timeout = match options.timeout {
        Some(seconds) => duration("timeout", seconds)?,
        None => DEFAULT_QUERY_TIMEOUT,
    };
    Ok(request)
}

fn deploy_request(
    rule_id: String,
    operation: &str,
    body: Vec<u8>,
) -> Result<DeployRequest, Failure> {
    let operation = match operation {
        "create" => Operation::Create,
        "update" => Operation::Update,
        "disable" => Operation::Disable,
        "delete" => Operation::Delete,
        other => {
            return Err(Failure::usage(format!(
                "operation: `{other}` is not create, update, disable or delete"
            )));
        }
    };
    Ok(DeployRequest {
        rule_id,
        operation,
        body,
    })
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Create => "create",
        Operation::Update => "update",
        Operation::Disable => "disable",
        Operation::Delete => "delete",
    }
}

fn duration(name: &str, seconds: f64) -> Result<Duration, Failure> {
    Duration::try_from_secs_f64(seconds)
        .map_err(|_| Failure::invalid(format!("{name}: {seconds} is not a number of seconds")))
}

fn instant(name: &str, text: &str) -> Result<Timestamp, Failure> {
    text.parse().map_err(|error| {
        Failure::invalid(format!(
            "{name}: `{text}` is not an RFC 3339 instant: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: &str = "2026-11-12T10:00:00Z";

    fn options(start: Option<&str>, end: Option<&str>) -> Option<QueryOptions> {
        Some(QueryOptions {
            start: start.map(str::to_owned),
            end: end.map(str::to_owned),
            ..QueryOptions::default()
        })
    }

    #[test]
    fn a_query_searches_the_day_and_a_check_the_minute_before_the_end() {
        let day = request("x".into(), options(None, Some(AT)), Since::Day).unwrap();
        assert_eq!(day.window.end, AT.parse::<Timestamp>().unwrap());
        assert_eq!(day.window.seconds(), 86_400);
        let minute = request("x".into(), options(None, Some(AT)), Since::Minute).unwrap();
        assert_eq!(minute.window.seconds(), 60);
        let given = request(
            "x".into(),
            options(Some("2026-11-12T09:00:00+00:00"), Some(AT)),
            Since::Minute,
        )
        .unwrap();
        assert_eq!(given.window.seconds(), 3_600);
        // No end: now.
        let now = request("x".into(), None, Since::Day).unwrap();
        assert!(now.window.end <= Timestamp::now());
        assert_eq!(now.limit, DEFAULT_LIMIT);
        assert_eq!(now.timeout, DEFAULT_QUERY_TIMEOUT);
        assert_eq!(now.language, "");
    }

    #[test]
    fn every_query_option_reaches_the_request() {
        let request = request(
            "event.type = 'x'".into(),
            Some(QueryOptions {
                language: Some("s1ql".into()),
                start: None,
                end: Some(AT.into()),
                limit: Some(7),
                index: Some(vec!["logs-*".into()]),
                data_view: Some("view".into()),
                timeout: Some(1.5),
            }),
            Since::Day,
        )
        .unwrap();
        assert_eq!(request.text, "event.type = 'x'");
        assert_eq!(request.language, "s1ql");
        assert_eq!(request.limit, 7);
        assert_eq!(request.index, ["logs-*"]);
        assert_eq!(request.data_view.as_deref(), Some("view"));
        assert_eq!(request.timeout, Duration::from_millis(1500));
    }

    #[test]
    fn a_window_or_timeout_that_does_not_read_is_a_usage_error() {
        for (start, end) in [
            (Some("2026-11-12T10:00:01Z"), Some(AT)),
            (Some("yesterday"), Some(AT)),
            (None, Some("soon")),
        ] {
            let failure = request("x".into(), options(start, end), Since::Day).unwrap_err();
            assert_eq!(failure.code, "usage_invalid_value", "{start:?}..{end:?}");
        }
        let slow = Some(QueryOptions {
            timeout: Some(-1.0),
            ..QueryOptions::default()
        });
        let failure = request("x".into(), slow, Since::Day).unwrap_err();
        assert_eq!(failure.code, "usage_invalid_value");
        assert!(failure.message.starts_with("timeout:"), "{failure:?}");
        for seconds in [-1.0, f64::NAN, f64::INFINITY] {
            assert!(duration("timeout", seconds).is_err(), "{seconds}");
        }
    }

    #[test]
    fn a_deploy_takes_the_four_operations() {
        for name in ["create", "update", "disable", "delete"] {
            let request = deploy_request("r".into(), name, b"{}".to_vec()).unwrap();
            assert_eq!(operation_name(request.operation), name);
            assert_eq!(
                (request.rule_id.as_str(), request.body.as_slice()),
                ("r", &b"{}"[..])
            );
        }
        let failure = deploy_request("r".into(), "upsert", Vec::new()).unwrap_err();
        assert_eq!(failure.code, "usage_invalid_choice");
        assert!(failure.message.contains("upsert"), "{failure:?}");
    }

    #[test]
    fn documents_keep_their_order_in_javascripts_names() {
        let row: connectors::Row = serde_json::from_str(r#"{"z":1,"a":"x"}"#).unwrap();
        let outcome = QueryOutcome {
            columns: vec![
                connectors::QueryColumn::named("z"),
                connectors::QueryColumn {
                    name: "a".into(),
                    kind: Some("string".into()),
                },
            ],
            rows: vec![row],
            truncated: true,
            vendor_query_id: Some("pq-1".into()),
            ..QueryOutcome::default()
        };
        assert_eq!(
            serde_json::to_string(&QueryResult::from(outcome.clone())).unwrap(),
            r#"{"columns":[{"name":"z","type":null},{"name":"a","type":"string"}],"rows":[{"z":1,"a":"x"}],"truncated":true,"partial":false,"warnings":[],"vendorQueryId":"pq-1","sent":null,"language":null}"#
        );
        let check = connectors::LiveCheck {
            result: Some(outcome),
            errors: vec!["missing Timestamp".into()],
            ..connectors::LiveCheck::default()
        };
        let check = serde_json::to_value(LiveCheck::from(check)).unwrap();
        assert_eq!(check["errors"][0], "missing Timestamp");
        assert_eq!(check["result"]["vendorQueryId"], "pq-1");
        let none = connectors::LiveCheck::default();
        assert_eq!(
            serde_json::to_string(&LiveCheck::from(none)).unwrap(),
            r#"{"result":null,"errors":[],"warnings":[]}"#
        );
        let deployed = connectors::DeployOutcome {
            remote_id: Some("42".into()),
            operation: Operation::Disable,
        };
        assert_eq!(
            serde_json::to_string(&DeployOutcome::from(deployed)).unwrap(),
            r#"{"remoteId":"42","operation":"disable"}"#
        );
    }

    #[test]
    fn the_platforms_and_what_each_can_do() {
        assert_eq!(platforms().len(), 9);
        assert!(platforms().contains(&"sentinel_one".to_owned()));
        assert_eq!(
            capabilities("sysdig".into()),
            Some(Capabilities {
                deploy: true,
                live_validation: false,
                query: false,
            })
        );
        assert_eq!(capabilities("nowhere".into()), None);
    }

    fn setup(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// The SentinelOne tenant `soc` at `url`, its token `$S1_API_TOKEN`.
    fn soc(url: &str) -> TenantConfig {
        TenantConfig::new(
            "sentinel_one".into(),
            "soc".into(),
            setup(&[
                ("url", url),
                ("api_token", "$S1_API_TOKEN"),
                ("account_id", "42"),
            ]),
        )
    }

    /// An environment of its own: no proxy of the process applies.
    fn environment(pairs: &[(&str, &str)]) -> Option<ConnectOptions> {
        Some(ConnectOptions {
            environment: Some(setup(pairs)),
            ..ConnectOptions::default()
        })
    }

    #[test]
    fn a_tenant_names_its_keys_never_their_values() {
        let tenant = soc("https://s1.example");
        assert_eq!(tenant.platform(), "sentinel_one");
        assert_eq!(tenant.name(), "soc");
        assert_eq!(tenant.setup_keys(), ["account_id", "api_token", "url"]);

        let files = HashMap::from([(
            ".opentide/configurations/platforms/splunk.toml".to_owned(),
            "[[tenants]]\nname = \"prod\"\n[tenants.setup]\nurl = \"$SPLUNK_URL\"\n\n\
             [[tenants]]\nname = \"lab\"\n[tenants.setup]\nurl = \"https://lab\"\n"
                .to_owned(),
        )]);
        let ws = crate::workspace_from_files("/ws".into(), files).unwrap();
        let names: Vec<String> = ws
            .tenants("splunk".into())
            .iter()
            .map(TenantConfig::name)
            .collect();
        assert_eq!(names, ["prod", "lab"]);
        assert!(ws.tenants("elastic".into()).is_empty());
    }

    #[test]
    fn opening_refuses_what_cannot_connect() {
        let nowhere =
            TenantConfig::new("nowhere".into(), "x".into(), setup(&[("url", "https://x")]));
        let unset = soc("https://s1.example");
        let bad_ssl = TenantConfig::new("splunk".into(), "prod".into(), setup(&[("ssl", "maybe")]));
        for (tenant, code) in [
            (&nowhere, "operation_unsupported"),
            (&unset, "credential_unset"),
            (&bad_ssl, "tenant_setup_invalid"),
        ] {
            let failure = open(tenant, environment(&[])).err().unwrap();
            assert_eq!(failure.code, code, "{failure:?}");
            assert_eq!(failure.detail, None);
        }
        let failure = open(&unset, environment(&[])).err().unwrap();
        assert!(failure.message.contains("S1_API_TOKEN"), "{failure:?}");
        let slow = Some(ConnectOptions {
            environment: Some(setup(&[("S1_API_TOKEN", "t")])),
            proxy: Some("http://127.0.0.1:9".into()),
            timeout: Some(f64::NAN),
        });
        assert_eq!(
            open(&unset, slow).err().unwrap().code,
            "usage_invalid_value"
        );
    }

    /// `work` on the SDK's runtime, as a promise runs it.
    fn run<T: Send + 'static>(
        work: impl Future<Output = Result<T, Failure>> + Send + 'static,
    ) -> Result<T, Failure> {
        runtime().unwrap().block_on(work)
    }

    #[test]
    fn a_connection_runs_its_operations_on_the_runtime() {
        // Nothing listens on port 9: the operations reach no tenant.
        let closed = soc("http://127.0.0.1:9");
        let connection = open(&closed, environment(&[("S1_API_TOKEN", "s3cret")])).unwrap();
        assert_eq!(
            (connection.platform(), connection.tenant()),
            ("sentinel_one".to_owned(), "soc".to_owned())
        );
        assert_eq!(
            connection.capabilities(),
            Capabilities {
                deploy: true,
                live_validation: true,
                query: true,
            }
        );
        let query = request("x".into(), None, Since::Day).unwrap();
        let failure = run(run_query(Arc::clone(&connection.inner), query.clone())).unwrap_err();
        assert_eq!(failure.code, "tenant_unreachable");
        assert!(!failure.message.contains("s3cret"), "{failure:?}");
        let failure = run(run_check(Arc::clone(&connection.inner), query.clone())).unwrap_err();
        assert_eq!(failure.code, "tenant_unreachable");
        let deploy = deploy_request("r".into(), "create", b"{}".to_vec()).unwrap();
        let failure = run(run_deploy(Arc::clone(&connection.inner), deploy)).unwrap_err();
        assert_eq!(failure.code, "tenant_unreachable");

        // A cancelled connection is interrupted, now and later.
        let canceller = connection.canceller();
        assert!(!canceller.is_cancelled());
        canceller.cancel();
        assert!(canceller.is_cancelled());
        let failure = run(run_query(Arc::clone(&connection.inner), query)).unwrap_err();
        assert_eq!(failure.code, "interrupted");
    }

    #[test]
    fn a_platform_that_cannot_check_live_says_so() {
        let lab = TenantConfig::new(
            "harfanglab".into(),
            "lab".into(),
            setup(&[("url", "http://127.0.0.1:9"), ("api_token", "t")]),
        );
        let connection = open(&lab, environment(&[])).unwrap();
        assert!(!connection.capabilities().live_validation);
        let check = request("x".into(), None, Since::Minute).unwrap();
        let failure = run(run_check(Arc::clone(&connection.inner), check)).unwrap_err();
        assert_eq!(failure.code, "operation_unsupported");
    }

    #[test]
    fn a_refusal_keeps_the_vendors_words() {
        let failure = Failure::from(opentide::Error::Connector {
            code: "tenant_refused",
            platform: "sentinel_one".into(),
            tenant: "soc".into(),
            message: "the tenant refused the query".into(),
            detail: Some("Syntax error at 3".into()),
        });
        assert_eq!(failure.code, "tenant_refused");
        assert_eq!(failure.detail.as_deref(), Some("Syntax error at 3"));
    }
}
