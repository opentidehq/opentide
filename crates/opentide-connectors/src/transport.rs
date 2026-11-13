//! The wire under every tenant's [`HttpClient`](crate::http::HttpClient): one
//! trait, [`Transport`], that sends a whole [`Request`] and returns a whole
//! [`Response`] (W2, `docs/engine/connector-transport.md`).
//!
//! Two implementations:
//!
//! - `ReqwestTransport` (every target but WASI, the default): reqwest on rustls, with the
//!   tenant's TLS, CA bundles, proxies, connect and read timeouts, HTTP/1.1.
//!   It is the client opentide always had, moved under the trait: what it
//!   sends and how it fails are unchanged, so the cassettes and goldens are.
//! - a transport the run installs ([`install`]): `opentide serve` installs
//!   one that asks its client to make each request (`opentide/fetch`), for
//!   the WASI build, where the host gives the process no sockets and the
//!   editor's own HTTP stack makes the call.
//!
//! What stays above the trait, in `HttpClient`, for both: the retries, the
//! in-flight limit, cancellation and the mapping to
//! [`ConnectorError`](crate::ConnectorError). A transport only reports which
//! way an exchange failed ([`TransportFailure`]).

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
#[cfg(not(target_os = "wasi"))]
use std::time::Instant;

use tokio_util::sync::CancellationToken;

use crate::connector::BoxFuture;
use crate::http::HttpSettings;
use crate::proxy::ProxySettings;
use crate::{Environment, TenantLabel};

pub use http::header::{self, HeaderMap, HeaderName, HeaderValue};
pub use http::{Method, StatusCode};

/// A request, whole: method, URL, headers in the order written, its body and
/// the request's own timeout when it sets one (HarfangLab's telemetry search).
#[derive(Clone, Debug)]
pub struct Request {
    method: Method,
    url: url::Url,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
    timeout: Option<Duration>,
}

impl Request {
    /// A request of *method* to *url*, no header, no body.
    pub fn new(method: Method, url: url::Url) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
            timeout: None,
        }
    }

    /// Its method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Its URL.
    pub fn url(&self) -> &url::Url {
        &self.url
    }

    /// Its headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Its headers, to change.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    /// Its body.
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }

    /// Sets its body.
    pub fn set_body(&mut self, body: Option<Vec<u8>>) {
        self.body = body;
    }

    /// Its own timeout, when it has one.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Sets its own timeout.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    #[cfg(not(target_os = "wasi"))]
    fn from_reqwest(request: &reqwest::Request) -> Self {
        Self {
            method: request.method().clone(),
            url: request.url().clone(),
            headers: request.headers().clone(),
            body: request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .map(<[u8]>::to_vec),
            timeout: request.timeout().copied(),
        }
    }

    #[cfg(not(target_os = "wasi"))]
    fn into_reqwest(self) -> reqwest::Request {
        let mut request = reqwest::Request::new(self.method, self.url);
        *request.headers_mut() = self.headers;
        *request.body_mut() = self.body.map(reqwest::Body::from);
        *request.timeout_mut() = self.timeout;
        request
    }
}

/// Why a request could not be built: its URL or a header does not parse.
#[derive(Clone, Debug)]
pub struct BuildError {
    /// The error's text.
    display: String,
    /// The text of it and of the errors under it, without the URL.
    described: String,
}

impl BuildError {
    fn message(message: String) -> Self {
        Self {
            display: message.clone(),
            described: message,
        }
    }

    #[cfg(not(target_os = "wasi"))]
    fn reqwest(error: reqwest::Error) -> Self {
        Self {
            display: error.to_string(),
            described: crate::error::describe(error),
        }
    }

    /// Its text, without the request's URL (which may carry a credential),
    /// as [`crate::error::describe`] gives a reqwest error's.
    pub fn describe(self) -> String {
        self.described
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display)
    }
}

impl std::error::Error for BuildError {}

/// A request being written ([`crate::http::HttpClient::request`]): reqwest's
/// builder natively, so a URL or header that does not parse is refused in
/// reqwest's words, as before the transport.
#[derive(Debug)]
pub struct RequestBuilder {
    inner: Inner,
}

#[derive(Debug)]
enum Inner {
    #[cfg(not(target_os = "wasi"))]
    Reqwest(reqwest::RequestBuilder),
    Plain(Result<Request, String>),
}

/// The client that builds requests natively: it never sends one (the
/// tenant's transport does), so it verifies nothing and trusts nothing.
#[cfg(not(target_os = "wasi"))]
fn builder_client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: std::sync::OnceLock<Result<reqwest::Client, String>> =
        std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            let settings = crate::tls::TlsSettings {
                verify: false,
                ca_bundle: None,
            };
            let tls = crate::tls::client_config(&settings, &Environment::default())?;
            reqwest::Client::builder()
                .tls_backend_preconfigured(tls)
                .no_proxy()
                .build()
                .map_err(crate::error::describe)
        })
        .as_ref()
        .map_err(Clone::clone)
}

impl RequestBuilder {
    pub(crate) fn new(method: Method, url: &str) -> Self {
        #[cfg(not(target_os = "wasi"))]
        if let Ok(client) = builder_client() {
            return Self {
                inner: Inner::Reqwest(client.request(method, url)),
            };
        }
        Self {
            inner: Inner::Plain(
                url::Url::parse(url)
                    .map(|url| Request::new(method, url))
                    .map_err(|error| format!("builder error: {error}")),
            ),
        }
    }

    /// Adds a header (a repeated name adds a value).
    #[must_use]
    pub fn header<K, V>(self, name: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        let inner = match self.inner {
            #[cfg(not(target_os = "wasi"))]
            Inner::Reqwest(builder) => Inner::Reqwest(builder.header(name, value)),
            Inner::Plain(request) => Inner::Plain(request.and_then(|mut request| {
                let name = HeaderName::try_from(name)
                    .map_err(|error| format!("builder error: {}", error.into()))?;
                let value = HeaderValue::try_from(value)
                    .map_err(|error| format!("builder error: {}", error.into()))?;
                request.headers.append(name, value);
                Ok(request)
            })),
        };
        Self { inner }
    }

    /// Sets the body.
    #[must_use]
    pub fn body(self, body: impl Into<Vec<u8>>) -> Self {
        let body: Vec<u8> = body.into();
        let inner = match self.inner {
            #[cfg(not(target_os = "wasi"))]
            Inner::Reqwest(builder) => Inner::Reqwest(builder.body(body)),
            Inner::Plain(request) => Inner::Plain(request.map(|mut request| {
                request.body = Some(body);
                request
            })),
        };
        Self { inner }
    }

    /// Sets this request's own timeout, in place of the tenant's read timeout.
    #[must_use]
    pub fn timeout(self, timeout: Duration) -> Self {
        let inner = match self.inner {
            #[cfg(not(target_os = "wasi"))]
            Inner::Reqwest(builder) => Inner::Reqwest(builder.timeout(timeout)),
            Inner::Plain(request) => Inner::Plain(request.map(|mut request| {
                request.timeout = Some(timeout);
                request
            })),
        };
        Self { inner }
    }

    /// The request.
    ///
    /// # Errors
    ///
    /// Its URL or a header does not parse.
    pub fn build(self) -> Result<Request, BuildError> {
        match self.inner {
            #[cfg(not(target_os = "wasi"))]
            Inner::Reqwest(builder) => builder
                .build()
                .map(|request| Request::from_reqwest(&request))
                .map_err(BuildError::reqwest),
            Inner::Plain(request) => request.map_err(BuildError::message),
        }
    }
}

/// An answer: its status, headers and URL, how long it took to come, and
/// its body, read whole, or why it could not be.
#[derive(Debug)]
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    url: url::Url,
    elapsed: Duration,
    reading: Duration,
    body: Result<Vec<u8>, TransportFailure>,
}

impl Response {
    /// An answer as a transport received it: *elapsed* from sending the
    /// request to its headers, *reading* spent reading its body.
    pub fn new(
        status: StatusCode,
        headers: HeaderMap,
        url: url::Url,
        (elapsed, reading): (Duration, Duration),
        body: Result<Vec<u8>, TransportFailure>,
    ) -> Self {
        Self {
            status,
            headers,
            url,
            elapsed,
            reading,
            body,
        }
    }

    /// How long reading its body took.
    pub fn reading(&self) -> Duration {
        self.reading
    }

    /// Its status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Its headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The URL that answered, after redirects.
    pub fn url(&self) -> &url::Url {
        &self.url
    }

    /// From sending the request to the answer's headers (`requests`'
    /// `elapsed`).
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Its body, or why it could not be read.
    pub(crate) fn into_body(self) -> Result<Vec<u8>, TransportFailure> {
        self.body
    }
}

/// Which way an exchange failed, before
/// [`HttpClient`](crate::http::HttpClient) names the tenant
/// ([`ConnectorError`](crate::ConnectorError)) and decides on a retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportFailure {
    /// No connection: refused, DNS, TLS, the proxy, or the connect limit.
    /// Sent again when the tenant's retry policy allows.
    Connect {
        /// What failed, without the URL.
        reason: String,
    },
    /// Connected, then no answer (or no more of it) within the read limit.
    Timeout,
    /// The request could not reach the tenant for another reason: a URL,
    /// header or setting the transport refuses. Never sent again.
    Unreachable {
        /// What failed, without the URL.
        reason: String,
    },
    /// The answer could not be read.
    Answer {
        /// What failed, without the URL.
        reason: String,
    },
    /// The run was cancelled.
    Cancelled,
}

/// The wire of one tenant.
pub trait Transport: Send + Sync + fmt::Debug {
    /// Sends *request* and reads its answer whole; stops with
    /// [`TransportFailure::Cancelled`] when *cancel* fires.
    fn execute<'a>(
        &'a self,
        request: Request,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Response, TransportFailure>>;
}

/// What a transport is made for: the tenant, its settings and its route.
#[derive(Debug)]
pub struct TransportSpec<'a> {
    /// The tenant.
    pub label: &'a TenantLabel,
    /// Its TLS, timeout and retries.
    pub settings: &'a HttpSettings,
    /// Its proxies.
    pub proxies: &'a ProxySettings,
    /// The run's environment (the CA bundle variables).
    pub env: &'a Environment,
}

/// Makes the transport of each tenant's client, in place of the default.
pub trait TransportFactory: Send + Sync {
    /// The transport of the tenant *spec* describes.
    ///
    /// # Errors
    ///
    /// The transport cannot be made (a setting it cannot honour): the text
    /// of the tenant's setup failure.
    fn make(&self, spec: &TransportSpec<'_>) -> Result<Arc<dyn Transport>, String>;
}

static INSTALLED: Mutex<Option<Arc<dyn TransportFactory>>> = Mutex::new(None);

/// Installs *factory* for every client built until the guard is dropped:
/// `opentide serve` does it for a client that answers `opentide/fetch`.
#[must_use = "the factory is uninstalled when the guard is dropped"]
pub fn install(factory: Arc<dyn TransportFactory>) -> Installed {
    let previous = INSTALLED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .replace(factory);
    Installed { previous }
}

/// Uninstalls the factory [`install`] installed when dropped, putting back
/// the one before it.
pub struct Installed {
    previous: Option<Arc<dyn TransportFactory>>,
}

impl fmt::Debug for Installed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Installed").finish_non_exhaustive()
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        *INSTALLED.lock().unwrap_or_else(PoisonError::into_inner) = self.previous.take();
    }
}

/// Why a tenant's transport could not be made.
#[derive(Debug)]
pub(crate) enum MakeError {
    /// A setting the transport cannot honour: the setup failure's text.
    Setup(String),
    /// The WASI build with no transport installed: no network at all.
    #[cfg_attr(
        not(target_os = "wasi"),
        expect(
            dead_code,
            reason = "only the WASI build's default transport has no network"
        )
    )]
    NetworkUnavailable,
}

/// The transport of the tenant *spec* describes: the installed factory's,
/// else the build's default.
pub(crate) fn make(spec: &TransportSpec<'_>) -> Result<Arc<dyn Transport>, MakeError> {
    let installed = INSTALLED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if let Some(factory) = installed {
        return factory.make(spec).map_err(MakeError::Setup);
    }
    default(spec)
}

#[cfg(not(target_os = "wasi"))]
fn default(spec: &TransportSpec<'_>) -> Result<Arc<dyn Transport>, MakeError> {
    Ok(Arc::new(
        ReqwestTransport::new(spec).map_err(MakeError::Setup)?,
    ))
}

#[cfg(target_os = "wasi")]
fn default(_spec: &TransportSpec<'_>) -> Result<Arc<dyn Transport>, MakeError> {
    // The host gives the process no sockets: only `opentide serve`, with a
    // client that answers `opentide/fetch`, reaches a tenant.
    Err(MakeError::NetworkUnavailable)
}

/// The native transport: reqwest on rustls.
#[cfg(not(target_os = "wasi"))]
#[derive(Debug)]
pub struct ReqwestTransport {
    client: reqwest::Client,
    /// Each read of the answer's body must bring data within it.
    read_timeout: Duration,
}

#[cfg(not(target_os = "wasi"))]
impl ReqwestTransport {
    /// The client of the tenant *spec* describes.
    ///
    /// # Errors
    ///
    /// A CA bundle that does not read, or a proxy that does not parse.
    pub fn new(spec: &TransportSpec<'_>) -> Result<Self, String> {
        let settings = spec.settings;
        let tls = crate::tls::client_config(&settings.tls, spec.env)?;
        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .http1_only()
            .connect_timeout(settings.timeout)
            // reqwest's read timeout runs from the start of the request, the
            // connection included, so at `timeout` it would race the connect
            // timeout and report a tenant that cannot be reached as a slow
            // one. `requests` gives the answer `timeout` once connected (at
            // most twice `timeout` from the start); the body's reads are held
            // to `timeout` each below.
            .read_timeout(settings.timeout.saturating_mul(2))
            .no_proxy();
        for proxy in spec.proxies.proxies()? {
            builder = builder.proxy(proxy);
        }
        let client = builder.build().map_err(crate::error::describe)?;
        Ok(Self {
            client,
            read_timeout: settings.timeout,
        })
    }

    /// Which way *error* failed, as `HttpClient` used to read reqwest's.
    fn failure(error: reqwest::Error) -> TransportFailure {
        if error.is_timeout() && !error.is_connect() {
            return TransportFailure::Timeout;
        }
        let connect = error.is_connect();
        let unreachable = connect || error.is_request() || error.is_timeout();
        let reason = crate::error::describe(error);
        if connect {
            TransportFailure::Connect { reason }
        } else if unreachable {
            TransportFailure::Unreachable { reason }
        } else {
            TransportFailure::Answer { reason }
        }
    }

    async fn body(
        mut response: reqwest::Response,
        read_timeout: Duration,
    ) -> Result<Vec<u8>, TransportFailure> {
        let mut body = Vec::new();
        loop {
            match tokio::time::timeout(read_timeout, response.chunk()).await {
                Ok(Ok(Some(chunk))) => body.extend_from_slice(&chunk),
                Ok(Ok(None)) => return Ok(body),
                Ok(Err(failure)) => return Err(Self::failure(failure)),
                Err(_) => return Err(TransportFailure::Timeout),
            }
        }
    }
}

#[cfg(not(target_os = "wasi"))]
impl Transport for ReqwestTransport {
    fn execute<'a>(
        &'a self,
        request: Request,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Response, TransportFailure>> {
        Box::pin(async move {
            let started = Instant::now();
            let exchange = async {
                let response = self
                    .client
                    .execute(request.into_reqwest())
                    .await
                    .map_err(Self::failure)?;
                let elapsed = started.elapsed();
                let status = response.status();
                let headers = response.headers().clone();
                let url = response.url().clone();
                let body = Self::body(response, self.read_timeout).await;
                let reading = started.elapsed().saturating_sub(elapsed);
                Ok(Response::new(
                    status,
                    headers,
                    url,
                    (elapsed, reading),
                    body,
                ))
            };
            // `biased`: a cancelled run is interrupted, never answered by
            // whichever branch tokio happens to poll first (#1034).
            tokio::select! {
                biased;
                () = cancel.cancelled() => Err(TransportFailure::Cancelled),
                outcome = exchange => outcome,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport that answers every request with 204 and names the tenant
    /// it was made for.
    #[derive(Debug)]
    struct Stub(String);

    impl Transport for Stub {
        fn execute<'a>(
            &'a self,
            request: Request,
            _cancel: &'a CancellationToken,
        ) -> BoxFuture<'a, Result<Response, TransportFailure>> {
            Box::pin(async move {
                let mut headers = HeaderMap::new();
                headers.insert(
                    "x-tenant",
                    HeaderValue::from_str(&self.0).map_err(|_| TransportFailure::Timeout)?,
                );
                Ok(Response::new(
                    StatusCode::NO_CONTENT,
                    headers,
                    request.url().clone(),
                    (Duration::ZERO, Duration::ZERO),
                    Ok(Vec::new()),
                ))
            })
        }
    }

    struct Stubs;

    impl TransportFactory for Stubs {
        fn make(&self, spec: &TransportSpec<'_>) -> Result<Arc<dyn Transport>, String> {
            if spec.label.tenant == "refused" {
                return Err("a setting the stub cannot honour".to_owned());
            }
            Ok(Arc::new(Stub(spec.label.tenant.clone())))
        }
    }

    #[test]
    fn an_installed_factory_makes_every_clients_transport_until_its_guard_drops() {
        use crate::{ConnectorError, HttpClient, HttpSettings};
        let client = |tenant: &str| {
            HttpClient::new(
                &TenantLabel::new("splunk", tenant),
                &HttpSettings::default(),
                &Environment::default(),
                None,
            )
        };
        let installed = install(Arc::new(Stubs));
        let lab = client("lab").map_err(|error| error.to_string());
        let Ok(lab) = lab else {
            panic!("{lab:?}");
        };
        let request = lab
            .request(Method::GET, "https://splunk.invalid:8089/q")
            .build();
        let Ok(request) = request else {
            panic!("{request:?}");
        };
        let answer = crate::runtime::block_on(lab.send(request, &CancellationToken::new()));
        let Ok(Ok(answer)) = answer else {
            panic!("{answer:?}");
        };
        assert_eq!(answer.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            answer
                .headers()
                .get("x-tenant")
                .and_then(|value| value.to_str().ok()),
            Some("lab")
        );
        assert!(matches!(
            client("refused"),
            Err(ConnectorError::Setup { message, .. }) if message == "a setting the stub cannot honour"
        ));
        drop(installed);
        // The build's own transport again.
        assert!(client("refused").is_ok());
    }

    #[test]
    fn a_build_without_a_network_names_its_failure_code() {
        let error = crate::ConnectorError::NetworkUnavailable {
            platform: "splunk".into(),
            tenant: "lab".into(),
        };
        assert_eq!(error.failure_code(), crate::error::NETWORK_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "this command needs the network, which the WASI build of opentide does not have; \
             run the opentide CLI"
        );
    }
}
