//! Tenant operations (feature `connectors`): run a query on a tenant, check a
//! query live, deploy a compiled rule, through the platform connectors
//! (tokio and reqwest on rustls) that `opentide query`,
//! `opentide validate query --live` and `opentide deploy` run on.
//!
//! A [`Connection`] is one tenant's client, built from that tenant's own
//! configuration ([`Workspace::tenants`]): its TLS and CA settings, its
//! proxy, its timeout and retries, its credentials. Its operations are
//! `async` and need a [tokio](https://tokio.rs) runtime: `.await` them in a
//! tokio task, or run one from synchronous code with [`block_on`].
//!
//! ```no_run
//! use opentide::connectors::{self, ConnectOptions, Connection, QueryRequest, TimeWindow, Timestamp};
//!
//! let ws = opentide::Workspace::open("path/to/workspace", &opentide::Options::default())?;
//! let tenant = &ws.tenants("splunk")[0];
//! let connection = Connection::open(tenant, &ConnectOptions::default())?;
//! let request = QueryRequest::new("index=main | head 5", "spl", TimeWindow::check(Timestamp::now()));
//! let outcome = connectors::block_on(connection.query(&request))??;
//! println!("{} rows", outcome.rows.len());
//! # Ok::<(), opentide::Error>(())
//! ```
//!
//! A query saves nothing on the tenant. A platform that cannot do an
//! operation (CrowdStrike, HarfangLab and Sysdig cannot check a query live;
//! Elastic and Sysdig deploy through `opentide deploy` only) answers it
//! with [`Error::Connector`] and the code `operation_unsupported`, never with
//! a faked result. A whole deploy run (the plan, the deployment state, the
//! retirements) is the command line's `deploy` (`cli::run_json`); a
//! [`Connection`] deploys one compiled rule.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use opentide_connectors::credentials::Mode;
use opentide_connectors::{ConnectorError, Environment, HttpClient, Platform, Registry, Tenant};
use tokio_util::sync::CancellationToken;

use crate::{Error, Workspace};

pub use jiff::Timestamp;
pub use opentide_connectors::connector::{
    DEFAULT_LIMIT, DEFAULT_QUERY_TIMEOUT, DeployOutcome, DeployRequest, LiveCheck, Operation,
    QueryColumn, QueryOutcome, QueryRequest, Row, TimeWindow,
};

/// The code of an operation the platform's connector does not have (a live
/// check on CrowdStrike), or of a platform without a connector.
pub const OPERATION_UNSUPPORTED: &str = "operation_unsupported";

/// The platforms with a connector, in the order opentide lists them.
///
/// ```
/// assert!(opentide::connectors::platforms().contains(&"splunk"));
/// ```
pub fn platforms() -> Vec<&'static str> {
    opentide_connectors::builtin().ids()
}

/// What a platform's connector can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Capabilities {
    /// [`Connection::deploy`].
    pub deploy: bool,
    /// [`Connection::validate_query`] (`validate query --live`).
    pub live_validation: bool,
    /// [`Connection::query`] (`opentide query`).
    pub query: bool,
}

/// What the connector of `platform` can do; `None` for a platform without
/// one.
///
/// ```
/// let crowdstrike = opentide::connectors::capabilities("crowdstrike").unwrap();
/// assert!(crowdstrike.query && !crowdstrike.live_validation);
/// assert_eq!(opentide::connectors::capabilities("nowhere"), None);
/// ```
pub fn capabilities(platform: &str) -> Option<Capabilities> {
    opentide_connectors::builtin()
        .get(platform)
        .map(capabilities_of)
}

fn capabilities_of(platform: &dyn Platform) -> Capabilities {
    Capabilities {
        deploy: platform.deployer().is_some(),
        live_validation: platform.live_validator().is_some(),
        query: platform.query_runner().is_some(),
    }
}

/// A tenant as the workspace configures it: an entry of `[[tenants]]` in
/// `.opentide/configurations/platforms/<platform>.toml`, its `setup` as
/// written (`$NAME` credentials unresolved). Its `Debug` names the setup's
/// keys, never their values.
#[derive(Clone, PartialEq)]
pub struct TenantConfig {
    platform: String,
    name: String,
    setup: toml::Table,
}

impl TenantConfig {
    /// The tenant `name` of `platform` with its `setup` table: a tenant
    /// configured in code rather than in the workspace.
    ///
    /// ```
    /// let tenant = opentide::connectors::TenantConfig::new(
    ///     "harfanglab",
    ///     "lab",
    ///     [("url", "https://hl.example"), ("api_token", "$HL_TOKEN"), ("type", "Sigma")],
    /// );
    /// assert_eq!((tenant.platform(), tenant.name()), ("harfanglab", "lab"));
    /// ```
    pub fn new<K: Into<String>, V: Into<String>>(
        platform: impl Into<String>,
        name: impl Into<String>,
        setup: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        Self {
            platform: platform.into(),
            name: name.into(),
            setup: setup
                .into_iter()
                .map(|(key, value)| (key.into(), toml::Value::String(value.into())))
                .collect(),
        }
    }

    /// The platform's identifier (`splunk`, `sentinel`).
    pub fn platform(&self) -> &str {
        &self.platform
    }

    /// The tenant's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The keys of its `setup`, in name order.
    pub fn setup_keys(&self) -> impl Iterator<Item = &str> {
        self.setup.keys().map(String::as_str)
    }
}

impl std::fmt::Debug for TenantConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantConfig")
            .field("platform", &self.platform)
            .field("name", &self.name)
            .field("setup", &self.setup.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Workspace {
    /// The tenants the workspace configures for `platform`, in file order;
    /// empty when it configures none.
    ///
    /// ```
    /// let ws = opentide::Workspace::from_files(
    ///     "/ws",
    ///     [(
    ///         ".opentide/configurations/platforms/splunk.toml",
    ///         "enabled = true\n[[tenants]]\nname = \"prod\"\n[tenants.setup]\nurl = \"$SPLUNK_URL\"\n",
    ///     )],
    /// )?;
    /// let tenants = ws.tenants("splunk");
    /// assert_eq!(tenants[0].name(), "prod");
    /// # Ok::<(), opentide::Error>(())
    /// ```
    pub fn tenants(&self, platform: &str) -> Vec<TenantConfig> {
        let config = opentide_compile::Json::from_node(&self.inner().configuration().resolved.tree);
        opentide_connectors::tenant::configured(&config, platform)
            .into_iter()
            .map(|(name, setup)| TenantConfig {
                platform: platform.to_owned(),
                name,
                setup,
            })
            .collect()
    }
}

/// How [`Connection::open`] reaches a tenant.
///
/// ```
/// let options = opentide::connectors::ConnectOptions::default()
///     .environment([("SPLUNK_TOKEN", "t0ken")])
///     .proxy("http://proxy.internal:3128");
/// assert_eq!(options.proxy.as_deref(), Some("http://proxy.internal:3128"));
/// ```
#[derive(Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConnectOptions {
    /// The environment the tenant's `$NAME` credentials, `ssl`, CA bundles
    /// (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`) and proxies
    /// (`OPENTIDE_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, ...) are read from.
    /// `None`: the process's, read when the connection opens.
    pub environment: Option<BTreeMap<String, String>>,
    /// The proxy every request goes through (`--proxy`), before the
    /// environment's.
    pub proxy: Option<String>,
    /// How long a tenant may take to answer a read, for the platforms whose
    /// client takes the caller's (Elastic, Splunk, Carbon Black Cloud,
    /// Sentinel); the others keep their own. Default:
    /// [`DEFAULT_QUERY_TIMEOUT`].
    pub timeout: Option<Duration>,
}

impl std::fmt::Debug for ConnectOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The environment holds credentials: its names only.
        f.debug_struct("ConnectOptions")
            .field(
                "environment",
                &self
                    .environment
                    .as_ref()
                    .map(|vars| vars.keys().collect::<Vec<_>>()),
            )
            .field("proxy", &self.proxy)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl ConnectOptions {
    /// Reads credentials, CA bundles and proxies from `vars` instead of the
    /// process's environment.
    pub fn environment<K: Into<String>, V: Into<String>>(
        mut self,
        vars: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        self.environment = Some(
            vars.into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        );
        self
    }

    /// Sends every request through `proxy`.
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Gives a tenant `timeout` to answer a read.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// One tenant's client: its HTTP client, built from the tenant's own
/// settings (never another tenant's), its resolved credentials, and the
/// platform's connector. Secrets never reach a message, a log or a `Debug`.
///
/// It is `Send + Sync`: one connection serves many operations, at once or in
/// turn, and keeps what the platform reuses between them (a sign-in token).
pub struct Connection {
    platform: String,
    tenant: Tenant,
    http: HttpClient,
    registry: Registry,
    cancel: CancellationToken,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("platform", &self.platform)
            .field("tenant", &self.tenant.label.tenant)
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// Connects to `tenant`: resolves its credentials (an unset `$NAME` is
    /// an error naming the variable) and builds its client. Nothing is sent
    /// until an operation runs.
    ///
    /// # Errors
    ///
    /// [`Error::Connector`]: `operation_unsupported` for a platform without
    /// a connector, `credential_unset` for an unset `$NAME`,
    /// `tenant_setup_invalid` for a setup the client cannot use (an `ssl`
    /// that is not a boolean, a CA bundle or proxy that does not read).
    pub fn open(tenant: &TenantConfig, options: &ConnectOptions) -> Result<Self, Error> {
        let registry = opentide_connectors::builtin();
        if registry.get(&tenant.platform).is_none() {
            return Err(unsupported(tenant, "has no connector"));
        }
        let environment = match &options.environment {
            Some(vars) => Environment::from_pairs(vars.clone()),
            None => Environment::process(),
        };
        let settings = opentide_connectors::http_settings(
            &tenant.platform,
            options.timeout.unwrap_or(DEFAULT_QUERY_TIMEOUT),
        );
        let resolved = Tenant::from_setup(
            &tenant.platform,
            &tenant.name,
            &tenant.setup,
            &environment,
            Mode::Required,
            &settings,
        )
        .map_err(Error::from)?;
        let http = HttpClient::new(
            &resolved.label,
            &resolved.http,
            &environment,
            options.proxy.as_deref(),
        )
        .map_err(Error::from)?;
        Ok(Self {
            platform: tenant.platform.clone(),
            tenant: resolved,
            http,
            registry,
            cancel: CancellationToken::new(),
        })
    }

    /// The platform's identifier.
    pub fn platform(&self) -> &str {
        &self.platform
    }

    /// The tenant's name.
    pub fn tenant(&self) -> &str {
        &self.tenant.label.tenant
    }

    /// What this tenant's connector can do.
    pub fn capabilities(&self) -> Capabilities {
        self.connector().map_or(
            Capabilities {
                deploy: false,
                live_validation: false,
                query: false,
            },
            capabilities_of,
        )
    }

    /// A handle that cancels this connection's operations from elsewhere
    /// (another task, a Ctrl-C handler).
    pub fn canceller(&self) -> Canceller {
        Canceller(self.cancel.clone())
    }

    fn connector(&self) -> Option<&dyn Platform> {
        self.registry.get(&self.platform)
    }

    fn context(&self) -> opentide_connectors::connector::TenantContext<'_> {
        opentide_connectors::connector::TenantContext {
            tenant: &self.tenant,
            http: &self.http,
            cancel: &self.cancel,
        }
    }

    fn unsupported(&self, what: &str) -> Error {
        Error::Connector {
            code: OPERATION_UNSUPPORTED,
            platform: self.platform.clone(),
            tenant: self.tenant().to_owned(),
            message: format!("{} {what}", self.platform),
            detail: None,
        }
    }

    /// Runs `request` on the tenant (`opentide query`) and returns its rows,
    /// at most `request.limit` (`truncated` when there were more). Nothing
    /// is saved on the tenant; a search this stops waiting for (cancelled,
    /// dropped) is stopped on the tenant where the API allows it.
    ///
    /// # Errors
    ///
    /// [`Error::Connector`]: `tenant_refused` when the tenant refuses the
    /// query (its message, the vendor's in `detail`), `query_timed_out`,
    /// `tenant_unreachable`, `authentication_failed`, `interrupted`, ...
    /// (the table on [`Error`]); `operation_unsupported` on a platform
    /// without a query runner (Sysdig).
    pub async fn query(&self, request: &QueryRequest) -> Result<QueryOutcome, Error> {
        let runner = self
            .connector()
            .and_then(Platform::query_runner)
            .ok_or_else(|| self.unsupported("has no query runner"))?;
        Ok(runner.run(self.context(), request).await?)
    }

    /// Checks `request` on the tenant (`opentide validate query --live`): by
    /// default a search for one row over its window, which
    /// [`TimeWindow::check`] sets to the minute before now. A query the
    /// tenant accepts returns a [`LiveCheck`]; its `errors` are why
    /// validation still fails it (Defender's required columns).
    ///
    /// # Errors
    ///
    /// [`Error::Connector`]: `tenant_refused` when the tenant refuses the
    /// query, and the other codes of [`Connection::query`];
    /// `operation_unsupported` on a platform that cannot check a query live
    /// (CrowdStrike, HarfangLab, Sysdig): never a faked verdict.
    pub async fn validate_query(&self, request: &QueryRequest) -> Result<LiveCheck, Error> {
        let validator = self
            .connector()
            .and_then(Platform::live_validator)
            .ok_or_else(|| self.unsupported("cannot check a query live"))?;
        Ok(validator.validate(self.context(), request).await?)
    }

    /// Applies `request` to the tenant: creates, updates, disables or
    /// deletes one rule from the body `opentide-compile` wrote (a deploy
    /// plan's payload for this tenant), sent as its bytes. Returns the
    /// platform's identifier of the rule, which a deploy keeps in deployment
    /// state.
    ///
    /// # Errors
    ///
    /// [`Error::Connector`]: `tenant_refused` when the tenant refuses the
    /// rule, and the other codes of [`Connection::query`];
    /// `operation_unsupported` on a platform whose rules deploy only through
    /// `opentide deploy` (Elastic).
    pub async fn deploy(&self, request: &DeployRequest) -> Result<DeployOutcome, Error> {
        let deployer = self
            .connector()
            .and_then(Platform::deployer)
            .ok_or_else(|| self.unsupported("has no deployer"))?;
        Ok(deployer.deploy(self.context(), request).await?)
    }
}

/// Cancels a [`Connection`]'s operations: the one running stops with the
/// code `interrupted` (a search stopped on the tenant where the API allows
/// it), and so does every later one. Cloning it is cheap.
#[derive(Debug, Clone)]
pub struct Canceller(CancellationToken);

impl Canceller {
    /// Cancels.
    pub fn cancel(&self) {
        self.0.cancel();
    }

    /// Whether [`Canceller::cancel`] was called.
    pub fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
}

/// Runs `work` (a [`Connection`]'s operation) to completion on a tokio
/// runtime of its own, for a synchronous caller. Call it outside any async
/// runtime: tokio refuses to start one inside another.
///
/// # Errors
///
/// [`Error::Connector`] with the code `runtime_unavailable` when the runtime
/// cannot start.
pub fn block_on<F: Future>(work: F) -> Result<F::Output, Error> {
    opentide_connectors::runtime::block_on(work).map_err(|message| Error::Connector {
        code: RUNTIME_UNAVAILABLE,
        platform: String::new(),
        tenant: String::new(),
        message,
        detail: None,
    })
}

/// The code of [`block_on`]'s failure to start its runtime.
pub const RUNTIME_UNAVAILABLE: &str = "runtime_unavailable";

fn unsupported(tenant: &TenantConfig, what: &str) -> Error {
    Error::Connector {
        code: OPERATION_UNSUPPORTED,
        platform: tenant.platform.clone(),
        tenant: tenant.name.clone(),
        message: format!("{} {what}", tenant.platform),
        detail: None,
    }
}

impl From<ConnectorError> for Error {
    fn from(error: ConnectorError) -> Self {
        let message = error.to_string();
        let (code, platform, tenant, detail) = match error {
            ConnectorError::Unreachable {
                platform, tenant, ..
            } => ("tenant_unreachable", platform, tenant, None),
            ConnectorError::Timeout {
                platform, tenant, ..
            } => ("tenant_timeout", platform, tenant, None),
            ConnectorError::Answer {
                platform, tenant, ..
            } => ("tenant_answer_invalid", platform, tenant, None),
            ConnectorError::Setup {
                platform, tenant, ..
            } => ("tenant_setup_invalid", platform, tenant, None),
            ConnectorError::MissingCredential {
                platform, tenant, ..
            } => ("credential_unset", platform, tenant, None),
            ConnectorError::Crashed {
                platform, tenant, ..
            } => ("connector_crashed", platform, tenant, None),
            ConnectorError::Refused {
                platform,
                tenant,
                detail,
                ..
            } => ("tenant_refused", platform, tenant, detail),
            ConnectorError::Authentication {
                platform,
                tenant,
                detail,
                ..
            } => ("authentication_failed", platform, tenant, detail),
            ConnectorError::QueryTimedOut {
                platform,
                tenant,
                detail,
                ..
            } => ("query_timed_out", platform, tenant, detail),
            ConnectorError::Gateway {
                platform, tenant, ..
            } => ("tenant_gateway", platform, tenant, None),
            ConnectorError::Cancelled => ("interrupted", String::new(), String::new(), None),
        };
        Self::Connector {
            code,
            platform,
            tenant,
            message,
            detail: detail.filter(|detail| !detail.is_empty()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who() -> (String, String) {
        ("splunk".to_owned(), "prod".to_owned())
    }

    #[test]
    fn every_connector_error_has_its_code_and_keeps_its_tenant() {
        let (platform, tenant) = who();
        let cases = [
            (
                ConnectorError::Unreachable {
                    platform: platform.clone(),
                    tenant: tenant.clone(),
                    address: "https://splunk.example:8089".into(),
                    reason: "connection refused".into(),
                },
                "tenant_unreachable",
            ),
            (
                ConnectorError::Timeout {
                    platform: platform.clone(),
                    tenant: tenant.clone(),
                    address: "https://splunk.example:8089".into(),
                    seconds: 5,
                },
                "tenant_timeout",
            ),
            (
                ConnectorError::Answer {
                    platform: platform.clone(),
                    tenant: tenant.clone(),
                    address: "https://splunk.example:8089".into(),
                    reason: "not JSON".into(),
                },
                "tenant_answer_invalid",
            ),
            (
                ConnectorError::Setup {
                    platform: platform.clone(),
                    tenant: tenant.clone(),
                    message: "url is missing".into(),
                },
                "tenant_setup_invalid",
            ),
            (
                ConnectorError::MissingCredential {
                    platform: platform.clone(),
                    tenant: tenant.clone(),
                    key: "token".into(),
                    variable: "SPLUNK_TOKEN".into(),
                },
                "credential_unset",
            ),
            (
                ConnectorError::Crashed {
                    platform: platform.clone(),
                    tenant: tenant.clone(),
                    message: "panicked".into(),
                },
                "connector_crashed",
            ),
            (
                ConnectorError::Gateway {
                    platform: platform.clone(),
                    tenant: tenant.clone(),
                    message: "a gateway answered".into(),
                    status: 504,
                },
                "tenant_gateway",
            ),
            (
                ConnectorError::QueryTimedOut {
                    platform: platform.clone(),
                    tenant: tenant.clone(),
                    message: "the search did not finish".into(),
                    detail: Some("narrow the window".into()),
                    timeout: Duration::from_secs(5),
                },
                "query_timed_out",
            ),
            (
                ConnectorError::authentication(&platform, &tenant, "bad token"),
                "authentication_failed",
            ),
            (
                ConnectorError::refused(&platform, &tenant, "refused", Some(String::new())),
                "tenant_refused",
            ),
        ];
        for (error, code) in cases {
            let message = error.to_string();
            let converted = Error::from(error);
            assert_eq!(converted.code(), code);
            assert_eq!(converted.to_string(), message);
            let Error::Connector {
                platform: on,
                tenant: at,
                detail,
                ..
            } = &converted
            else {
                panic!("{converted:?}");
            };
            assert_eq!((on, at), (&platform, &tenant));
            // An empty detail is none.
            assert_eq!(
                detail.as_deref(),
                (code == "query_timed_out").then_some("narrow the window")
            );
        }
        let cancelled = Error::from(ConnectorError::Cancelled);
        assert_eq!(cancelled.code(), "interrupted");
        assert_eq!(cancelled.to_string(), "interrupted");
    }

    #[test]
    fn the_options_build() {
        let options = ConnectOptions::default()
            .environment([("A", "1")])
            .proxy("http://proxy:3128")
            .timeout(Duration::from_secs(9));
        assert_eq!(options.timeout, Some(Duration::from_secs(9)));
        assert_eq!(
            options.environment.as_ref().and_then(|vars| vars.get("A")),
            Some(&"1".to_owned())
        );
    }
}
