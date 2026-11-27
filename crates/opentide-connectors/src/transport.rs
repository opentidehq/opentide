//! The wire under every tenant's [`HttpClient`](crate::http::HttpClient): one
//! trait, [`Transport`], that sends a whole [`Request`] and returns a whole
//! [`Response`] (W2, `docs/engine/connector-transport.md`).
//!
//! Two implementations:
//!
//! - `ReqwestTransport` (every target but WASI, the default): reqwest on rustls, with the
//!   tenant's TLS, CA bundles, proxies, connect and read timeouts; HTTP/2
//!   when the tenant offers it (ALPN), else HTTP/1.1.
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

/// A request, whole: method, URL, headers in the order written, its body,
/// the request's own timeout when it sets one (HarfangLab's telemetry
/// search), and whether it may be sent again after an answer when that is
/// not its method's (Sysdig's versioned `PUT`).
///
/// Its `Debug` shows the URL without its query or credentials, each header
/// name with a credential's value hidden, and the body's length only.
#[derive(Clone)]
pub struct Request {
    method: Method,
    url: url::Url,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
    timeout: Option<Duration>,
    idempotent: Option<bool>,
    read_only: bool,
}

/// The headers that carry a credential (#1142): marked sensitive when set,
/// so no `Debug` and no HTTP/2 header table shows or keeps their value.
const CREDENTIAL_HEADERS: [&str; 5] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-auth-token",
    "x-api-key",
];

/// Whether *name* carries a credential ([`CREDENTIAL_HEADERS`]).
pub(crate) fn is_credential_header(name: &HeaderName) -> bool {
    CREDENTIAL_HEADERS.contains(&name.as_str())
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut url = self.url.clone();
        url.set_query(None);
        url.set_fragment(None);
        let _ = url.set_username("");
        let _ = url.set_password(None);
        let headers: Vec<(&str, &dyn std::fmt::Debug)> = self
            .headers
            .iter()
            .map(|(name, value)| {
                let shown: &dyn std::fmt::Debug =
                    if value.is_sensitive() || is_credential_header(name) {
                        &"***"
                    } else {
                        value
                    };
                (name.as_str(), shown)
            })
            .collect();
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &url.as_str())
            .field("headers", &headers)
            .field("body_bytes", &self.body.as_ref().map(Vec::len))
            .field("timeout", &self.timeout)
            .field("idempotent", &self.idempotent)
            .field("read_only", &self.read_only)
            .finish()
    }
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
            idempotent: None,
            read_only: false,
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

    /// Whether sending it twice leaves the tenant as sending it once, so
    /// that a transient answer may be retried: its method's
    /// ([`RetryPolicy::is_idempotent`](crate::retry::RetryPolicy::is_idempotent))
    /// unless [`set_idempotent`](Self::set_idempotent) said otherwise.
    pub fn is_idempotent(&self) -> bool {
        self.idempotent
            .unwrap_or_else(|| crate::retry::RetryPolicy::is_idempotent(&self.method))
    }

    /// Marks it idempotent or not, whatever its method: a `PUT` that
    /// carries the version it replaces (optimistic concurrency) is not, as
    /// a second copy after the tenant applied the first names a stale
    /// version.
    pub fn set_idempotent(&mut self, idempotent: bool) {
        self.idempotent = Some(idempotent);
    }

    /// Whether it changes nothing on the tenant, whatever its method: a
    /// `GET`, `HEAD` or `OPTIONS`, or a request marked so
    /// ([`set_read_only`](Self::set_read_only)).
    pub fn is_read_only(&self) -> bool {
        self.read_only || matches!(self.method, Method::GET | Method::HEAD | Method::OPTIONS)
    }

    /// Marks a request that changes nothing on the tenant although its
    /// method could (a sign-in's `POST`, a query check's): what
    /// [`HttpClient::writes_taken`](crate::HttpClient::writes_taken) does
    /// not count.
    pub fn set_read_only(&mut self, read_only: bool) {
        self.read_only = read_only;
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

/// Why a request could not be built: its URL or a header does not parse. Its
/// text never carries the request's URL (which may hold a credential).
#[derive(Clone, Debug)]
pub struct BuildError {
    message: String,
}

impl BuildError {
    /// Its text, without the request's URL.
    #[must_use]
    pub fn describe(self) -> String {
        self.message
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BuildError {}

/// A request being written ([`crate::http::HttpClient::request`]): a URL or
/// header that does not parse is kept as the error [`build`](Self::build)
/// answers with.
#[derive(Debug)]
pub struct RequestBuilder {
    request: Result<Request, String>,
}

impl RequestBuilder {
    pub(crate) fn new(method: Method, url: &str) -> Self {
        Self {
            request: url::Url::parse(url)
                .map_err(|error| format!("builder error: {error}"))
                // `mailto:x`, `file:///x` and `data:` name no host to ask.
                .and_then(|url| {
                    if url.has_host() {
                        Ok(Request::new(method, url))
                    } else {
                        Err("builder error: URL scheme is not allowed".to_owned())
                    }
                }),
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
        self.with(|request| {
            let name = HeaderName::try_from(name)
                .map_err(|error| format!("builder error: {}", error.into()))?;
            let mut value = HeaderValue::try_from(value)
                .map_err(|error| format!("builder error: {}", error.into()))?;
            if is_credential_header(&name) {
                value.set_sensitive(true);
            }
            request.headers.append(name, value);
            Ok(())
        })
    }

    /// Sets `Authorization: Basic` for *username* and *password* (an absent
    /// password is empty): the value is marked sensitive.
    #[must_use]
    pub fn basic_auth(self, username: &str, password: Option<&str>) -> Self {
        self.with(|request| {
            use base64::Engine as _;
            let pair = format!("{username}:{}", password.unwrap_or(""));
            let encoded = base64::engine::general_purpose::STANDARD.encode(pair);
            let mut value = HeaderValue::try_from(format!("Basic {encoded}"))
                .map_err(|error| format!("builder error: {error}"))?;
            value.set_sensitive(true);
            request.headers.insert(header::AUTHORIZATION, value);
            Ok(())
        })
    }

    /// Sets the body.
    #[must_use]
    pub fn body(self, body: impl Into<Vec<u8>>) -> Self {
        let body: Vec<u8> = body.into();
        self.with(|request| {
            request.body = Some(body);
            Ok(())
        })
    }

    /// Marks the request as one that changes nothing on the tenant
    /// ([`Request::set_read_only`]).
    #[must_use]
    pub fn read_only(self) -> Self {
        self.with(|request| {
            request.read_only = true;
            Ok(())
        })
    }

    /// Sets this request's own timeout, in place of the tenant's read timeout.
    #[must_use]
    pub fn timeout(self, timeout: Duration) -> Self {
        self.with(|request| {
            request.timeout = Some(timeout);
            Ok(())
        })
    }

    /// Changes the request, unless an earlier step already failed.
    fn with(self, change: impl FnOnce(&mut Request) -> Result<(), String>) -> Self {
        Self {
            request: self.request.and_then(|mut request| {
                change(&mut request)?;
                Ok(request)
            }),
        }
    }

    /// The request.
    ///
    /// # Errors
    ///
    /// Its URL or a header does not parse.
    pub fn build(self) -> Result<Request, BuildError> {
        self.request.map_err(|message| BuildError { message })
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
    /// No connection: refused, DNS, the proxy, or the connect limit. Sent
    /// again when the tenant's retry policy allows.
    Connect {
        /// What failed, without the URL.
        reason: String,
    },
    /// Connected, then no answer (or no more of it) within the read limit,
    /// or the whole exchange ran past its deadline
    /// (`ReqwestTransport`'s [`DEADLINE_READ_TIMEOUTS`]).
    Timeout,
    /// The tenant's certificate was refused during the TLS handshake (the
    /// tenant's TLS settings do not trust it): the request was never sent.
    /// Never sent again: it would fail the same way.
    CertificateRefused {
        /// What failed, without the URL.
        reason: String,
    },
    /// The request could not reach the tenant for another reason: a URL,
    /// header or setting the transport refuses, or a connection dropped
    /// while the request was sent (it may have been taken). Never sent
    /// again: it would fail the same way.
    Unreachable {
        /// What failed, without the URL.
        reason: String,
    },
    /// The answer could not be read, or its body is larger than
    /// [`MAX_BODY_BYTES`].
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

/// Whether *error* is a TLS handshake that failed on the certificate: the
/// tenant's certificate is not trusted, has expired or names another host,
/// or none was presented. Sending again would fail the same way. rustls's
/// error reaches reqwest's chain inside `io::Error`s (hyper-util wraps
/// tokio-rustls's), whose `source` skips what they wrap, so an `io::Error`
/// is opened with `get_ref` instead.
#[cfg(not(target_os = "wasi"))]
fn certificate_refused(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if matches!(
            error.downcast_ref::<rustls::Error>(),
            Some(
                rustls::Error::InvalidCertificate(_)
                    | rustls::Error::NoCertificatesPresented
                    | rustls::Error::InvalidCertRevocationList(_)
            )
        ) {
            return true;
        }
        current = match error.downcast_ref::<std::io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => error.source(),
        };
    }
    false
}

#[cfg(all(test, not(target_os = "wasi")))]
mod certificate_tests {
    use super::certificate_refused;
    use std::io;

    /// hyper-util's chain: an `io::Error` around tokio-rustls's
    /// `io::Error` around rustls's error.
    #[test]
    fn a_certificate_error_is_found_inside_nested_io_errors() {
        let rustls = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        let nested = io::Error::other(io::Error::new(io::ErrorKind::InvalidData, rustls));
        assert!(certificate_refused(&nested));
        let other = io::Error::other(io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::DecryptError,
        ));
        assert!(!certificate_refused(&other));
        assert!(!certificate_refused(&io::Error::from(
            io::ErrorKind::ConnectionRefused
        )));
    }
}

/// The largest answer body a request reads: 64 MiB. No platform answers
/// one page that large; a body past it (a misrouted download, a gateway that
/// never stops) fails the request with [`TransportFailure::Answer`] instead
/// of filling the memory (#1936). A `Content-Length` past it fails before
/// the body is read.
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// How many read timeouts one exchange may take in all, after its connect
/// timeout: its deadline is the connect timeout plus this many read
/// timeouts (the request's own timeout when it is longer), 10 minutes with
/// the default 2-minute timeout. Each read must still bring data within one
/// read timeout; the deadline stops an answer that trickles in forever
/// (#1936), with [`TransportFailure::Timeout`].
pub const DEADLINE_READ_TIMEOUTS: u32 = 4;

/// The native transport: reqwest on rustls.
#[cfg(not(target_os = "wasi"))]
#[derive(Debug)]
pub struct ReqwestTransport {
    client: reqwest::Client,
    /// The connect limit, the first part of each exchange's deadline.
    connect_timeout: Duration,
    /// Each read of the answer's body must bring data within it.
    read_timeout: Duration,
    /// The largest body read ([`MAX_BODY_BYTES`]).
    max_body: usize,
}

/// How many redirects one request follows, as reqwest's default.
#[cfg(not(target_os = "wasi"))]
const MAX_REDIRECTS: usize = 10;

/// Whether a redirect from *from* to *to* is followed: on the same origin,
/// or from `http` to `https` on the same host (the credentials already went
/// out in clear on the first request). Any other hop leaves the tenant:
/// reqwest strips `Authorization` there, but not a platform's own header
/// (Carbon Black's `X-Auth-Token`, Bitdefender's `X-API-Key`), which would
/// reach that host (#1142).
pub fn follows_redirect(from: &url::Url, to: &url::Url) -> bool {
    if from.origin() == to.origin() {
        return true;
    }
    from.scheme() == "http"
        && to.scheme() == "https"
        && from.host() == to.host()
        && from.port().is_none()
        && to.port().is_none()
}

/// [`follows_redirect`]'s hops, at most [`MAX_REDIRECTS`]; a redirect it
/// stops at is the answer, a 3xx the connectors take as a failure.
#[cfg(not(target_os = "wasi"))]
fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        let follows = attempt
            .previous()
            .last()
            .is_none_or(|from| follows_redirect(from, attempt.url()));
        if follows {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
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
        let mut tls = crate::tls::client_config(&settings.tls, spec.env)?;
        // A preconfigured TLS backend offers only the protocols it names:
        // HTTP/2 when the tenant (or its gateway) speaks it, else HTTP/1.1.
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connect_timeout = settings.timeout;
        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .connect_timeout(connect_timeout)
            // reqwest starts its read timer with the request, the connection
            // included: the answer's head gets `timeout` once the connect
            // timeout has run, so a tenant that cannot be reached is reported
            // as one (a connect failure), never as a slow answer. The body's
            // reads are held to `timeout` each below.
            .read_timeout(connect_timeout.saturating_add(settings.timeout))
            .redirect(redirect_policy())
            .no_proxy();
        for proxy in spec.proxies.proxies()? {
            builder = builder.proxy(proxy);
        }
        let client = builder.build().map_err(crate::error::describe)?;
        Ok(Self {
            client,
            connect_timeout,
            read_timeout: settings.timeout,
            max_body: MAX_BODY_BYTES,
        })
    }

    /// How long an exchange of *request* may take in all
    /// ([`DEADLINE_READ_TIMEOUTS`]).
    fn deadline(&self, request: &Request) -> Duration {
        let read = request
            .timeout()
            .map_or(self.read_timeout, |own| own.max(self.read_timeout));
        self.connect_timeout
            .saturating_add(read.saturating_mul(DEADLINE_READ_TIMEOUTS))
    }

    /// Why a body of *size* bytes is not read.
    fn too_large(size: impl fmt::Display, max_body: usize) -> TransportFailure {
        TransportFailure::Answer {
            reason: format!("the answer's body ({size} bytes) is larger than {max_body} bytes"),
        }
    }

    /// Which way *error* failed, as `HttpClient` used to read reqwest's.
    fn failure(error: reqwest::Error) -> TransportFailure {
        if error.is_timeout() && !error.is_connect() {
            return TransportFailure::Timeout;
        }
        let connect = error.is_connect();
        let unreachable = connect || error.is_request() || error.is_timeout();
        let refused = certificate_refused(&error);
        let reason = crate::error::describe(error);
        if connect && !refused {
            TransportFailure::Connect { reason }
        } else if refused {
            TransportFailure::CertificateRefused { reason }
        } else if unreachable {
            TransportFailure::Unreachable { reason }
        } else {
            TransportFailure::Answer { reason }
        }
    }

    /// The body of *response*: each read within `read_timeout`, all of it
    /// by *deadline*, at most `max_body` bytes.
    async fn body(
        &self,
        mut response: reqwest::Response,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<u8>, TransportFailure> {
        if let Some(length) = response.content_length()
            && usize::try_from(length).map_or(true, |length| length > self.max_body)
        {
            return Err(Self::too_large(length, self.max_body));
        }
        let mut body = Vec::new();
        loop {
            let read = tokio::time::timeout(self.read_timeout, response.chunk());
            match tokio::time::timeout_at(deadline, read).await {
                Ok(Ok(Ok(Some(chunk)))) => {
                    let size = body.len().saturating_add(chunk.len());
                    if size > self.max_body {
                        return Err(Self::too_large(format!("at least {size}"), self.max_body));
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(Ok(Ok(None))) => return Ok(body),
                Ok(Ok(Err(failure))) => return Err(Self::failure(failure)),
                Ok(Err(_)) | Err(_) => return Err(TransportFailure::Timeout),
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
            let now = tokio::time::Instant::now();
            // A timeout too long for the clock has no deadline but the far
            // future (tokio's own, 30 years).
            let deadline = now
                .checked_add(self.deadline(&request))
                .unwrap_or_else(|| now + Duration::from_hours(24 * 365 * 30));
            let exchange = async {
                let response =
                    tokio::time::timeout_at(deadline, self.client.execute(request.into_reqwest()))
                        .await
                        .map_err(|_| TransportFailure::Timeout)?
                        .map_err(Self::failure)?;
                let elapsed = started.elapsed();
                let status = response.status();
                let headers = response.headers().clone();
                let url = response.url().clone();
                let body = self.body(response, deadline).await;
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

    /// A server on a free local port that answers each connection with
    /// what *answer* writes on the open socket, after reading the request.
    #[cfg(not(target_os = "wasi"))]
    fn serve(answer: impl Fn(&mut std::net::TcpStream) + Send + 'static) -> String {
        use std::io::Read as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    return;
                };
                let mut buffer = [0_u8; 4096];
                let _ = stream.read(&mut buffer);
                answer(&mut stream);
            }
        });
        format!("http://{address}/")
    }

    /// GET *url* through a [`ReqwestTransport`] whose timeouts are *timeout*
    /// and whose largest body is *max_body*.
    #[cfg(not(target_os = "wasi"))]
    fn fetch(url: &str, timeout: Duration, max_body: usize) -> Result<Response, TransportFailure> {
        let settings = crate::HttpSettings {
            timeout,
            ..crate::HttpSettings::default()
        };
        let spec = TransportSpec {
            label: &TenantLabel::new("splunk", "lab"),
            settings: &settings,
            proxies: &ProxySettings::default(),
            env: &Environment::default(),
        };
        let mut transport = ReqwestTransport::new(&spec).unwrap();
        transport.max_body = max_body;
        let request = Request::new(Method::GET, url::Url::parse(url).unwrap());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(transport.execute(request, &CancellationToken::new()))
    }

    #[cfg(not(target_os = "wasi"))]
    fn too_large(outcome: Result<Response, TransportFailure>) -> String {
        match outcome.map(Response::into_body) {
            Ok(Err(TransportFailure::Answer { reason })) => reason,
            other => panic!("not refused as too large: {other:?}"),
        }
    }

    /// A body up to the cap is read; a `Content-Length` past it is refused
    /// before the body, and a body streamed past it is refused once it
    /// passes (#1936).
    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn a_body_past_the_cap_is_refused() {
        use std::io::Write as _;
        let exact = serve(|stream| {
            let mut answer = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n".to_vec();
            answer.extend_from_slice("é😀abcd".as_bytes());
            let _ = stream.write_all(&answer);
        });
        let body = fetch(&exact, Duration::from_secs(5), 10)
            .unwrap()
            .into_body();
        assert_eq!(body.unwrap(), "é😀abcd".as_bytes());
        let declared = serve(|stream| {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n0123456789a");
        });
        assert_eq!(
            too_large(fetch(&declared, Duration::from_secs(5), 10)),
            "the answer's body (11 bytes) is larger than 10 bytes"
        );
        // Chunked, without a length, and never ending: refused at the cap.
        let streamed = serve(|stream| {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            while stream.write_all(b"4\r\nabcd\r\n").is_ok() {
                let _ = stream.flush();
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let reason = too_large(fetch(&streamed, Duration::from_secs(5), 10));
        assert!(
            reason.starts_with("the answer's body (at least "),
            "{reason}"
        );
        assert!(
            reason.ends_with(" bytes) is larger than 10 bytes"),
            "{reason}"
        );
    }

    /// An answer that sends a byte before each read timeout runs out, and
    /// never ends, stops at the exchange's deadline: the connect timeout
    /// plus [`DEADLINE_READ_TIMEOUTS`] read timeouts (#1936).
    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn an_answer_that_trickles_forever_stops_at_the_deadline() {
        use std::io::Write as _;
        let trickle = serve(|stream| {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            while stream.write_all(b"1\r\na\r\n").is_ok() {
                let _ = stream.flush();
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let started = Instant::now();
        let body =
            fetch(&trickle, Duration::from_millis(200), MAX_BODY_BYTES).map(Response::into_body);
        let took = started.elapsed();
        assert!(
            matches!(body, Ok(Err(TransportFailure::Timeout))),
            "{body:?}"
        );
        // 200 ms + 4 × 200 ms = 1 s, not the minute of trickling.
        assert!(took >= Duration::from_millis(900), "{took:?}");
        assert!(took < Duration::from_secs(10), "{took:?}");
    }

    /// An answer that stalls after its head times out on one read, long
    /// before the deadline.
    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn an_answer_that_stalls_times_out_on_one_read() {
        use std::io::Write as _;
        let stall = serve(|stream| {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab");
            let _ = stream.flush();
            std::thread::sleep(Duration::from_secs(5));
        });
        let started = Instant::now();
        let body =
            fetch(&stall, Duration::from_millis(200), MAX_BODY_BYTES).map(Response::into_body);
        assert!(
            matches!(body, Ok(Err(TransportFailure::Timeout))),
            "{body:?}"
        );
        assert!(
            started.elapsed() < Duration::from_millis(900),
            "{:?}",
            started.elapsed()
        );
    }

    /// The deadline is the connect timeout plus four read timeouts, of the
    /// request's own timeout when it is the longer.
    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn the_deadline_follows_the_timeouts() {
        let spec = TransportSpec {
            label: &TenantLabel::new("splunk", "lab"),
            settings: &crate::HttpSettings::default(),
            proxies: &ProxySettings::default(),
            env: &Environment::default(),
        };
        let transport = ReqwestTransport::new(&spec).unwrap();
        let url = url::Url::parse("https://splunk.invalid/").unwrap();
        let mut request = Request::new(Method::GET, url);
        assert_eq!(transport.deadline(&request), Duration::from_secs(600));
        request.set_timeout(Some(Duration::from_secs(300)));
        assert_eq!(transport.deadline(&request), Duration::from_mins(2 + 20));
        request.set_timeout(Some(Duration::from_secs(1)));
        assert_eq!(transport.deadline(&request), Duration::from_secs(600));
    }

    /// #1142: a request's credentials are sensitive, and its `Debug` shows
    /// none of them: not the headers, the URL's query or user, or the body.
    #[test]
    fn a_requests_credentials_are_sensitive_and_never_shown() {
        let mut builder = RequestBuilder::new(
            Method::POST,
            "https://user:pass@tenant.example/api?key=query-secret",
        )
        .header("Authorization", "Bearer bearer-secret")
        .header("X-Auth-Token", "token-secret")
        .header("X-API-Key", "key-secret")
        .header("Accept", "application/json")
        .body(b"client_secret=body-secret".to_vec());
        builder = builder.basic_auth("u", Some("basic-secret"));
        let request = builder.build().unwrap();
        for name in ["x-auth-token", "x-api-key", "authorization"] {
            assert!(
                request.headers().get(name).unwrap().is_sensitive(),
                "{name}"
            );
        }
        assert!(!request.headers().get("accept").unwrap().is_sensitive());
        let shown = format!("{request:?}");
        for secret in [
            "bearer-secret",
            "token-secret",
            "key-secret",
            "query-secret",
            "pass",
            "body-secret",
            "basic",
        ] {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }
        assert!(
            shown.contains("application/json") && shown.contains("https://tenant.example/api"),
            "{shown}"
        );
    }

    /// A URL or header that does not parse is refused in words, with no URL
    /// in them, whichever step failed first.
    #[test]
    fn a_request_that_does_not_parse_says_why() {
        let build = |url: &str| RequestBuilder::new(Method::GET, url);
        let reasons = [
            (build("not a url"), "relative URL without a base"),
            (build("mailto:x@example.test"), "URL scheme is not allowed"),
            (build("file:///etc/hosts"), "URL scheme is not allowed"),
            (build("data:text/plain,x"), "URL scheme is not allowed"),
            (
                build("https://u:p@a.example/").header("bad name", "v"),
                "invalid HTTP header name",
            ),
            (
                build("https://a.example/").header("x", "a\nb"),
                "failed to parse header value",
            ),
        ];
        for (builder, reason) in reasons {
            let error = builder.timeout(Duration::from_secs(1)).build().unwrap_err();
            assert_eq!(error.to_string(), format!("builder error: {reason}"));
            assert_eq!(error.describe(), format!("builder error: {reason}"));
        }
    }

    #[test]
    fn a_request_is_built_as_written() {
        let request = RequestBuilder::new(Method::POST, "https://a.example/p?q=1")
            .header("x-a", "1")
            .header("x-a", "2")
            .basic_auth("user", None)
            .body("body")
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        assert_eq!(request.url().as_str(), "https://a.example/p?q=1");
        assert_eq!(request.headers().get_all("x-a").iter().count(), 2);
        let auth = request.headers().get(header::AUTHORIZATION).unwrap();
        assert_eq!(auth, "Basic dXNlcjo=");
        assert!(auth.is_sensitive());
    }

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
