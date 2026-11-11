//! The HTTP client of one tenant: `TenantSession` in Rust.
//!
//! One [`HttpClient`] per tenant, built from that tenant's [`HttpSettings`]
//! and the run's environment: TLS on or off and the CA bundles it trusts
//! ([`crate::tls`]), the proxy ([`crate::proxy`]), a timeout on connecting
//! and on each read of the answer (`requests`' `timeout`, 120 s when a
//! platform names none: `transport.DEFAULT_TIMEOUT`), the retries
//! ([`crate::retry`]) and how many requests may be in flight to it at once.
//! HTTP/1.1, as `requests` speaks it; no default `User-Agent`, compression or
//! redirects beyond reqwest's.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::error::{self, ConnectorError};
use crate::proxy::ProxySettings;
use crate::retry::RetryPolicy;
use crate::tls::TlsSettings;
use crate::{Environment, TenantLabel};

/// `transport.DEFAULT_TIMEOUT`: seconds a tenant has to accept a connection
/// and then to send each part of its answer, when a platform names none.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// How one tenant is reached.
#[derive(Clone, Debug, PartialEq)]
pub struct HttpSettings {
    /// TLS verification and CA bundle.
    pub tls: TlsSettings,
    /// The connect timeout and the read timeout.
    pub timeout: Duration,
    /// When a request is sent again.
    pub retry: RetryPolicy,
    /// Requests in flight to this tenant at once.
    pub max_in_flight: usize,
}

impl Default for HttpSettings {
    fn default() -> Self {
        Self {
            tls: TlsSettings::default(),
            timeout: DEFAULT_TIMEOUT,
            retry: RetryPolicy::none(),
            max_in_flight: 4,
        }
    }
}

/// A tenant's client.
#[derive(Clone, Debug)]
pub struct HttpClient {
    client: reqwest::Client,
    label: TenantLabel,
    settings: HttpSettings,
    permits: Arc<Semaphore>,
}

impl HttpClient {
    /// The client of the tenant *label*, from its *settings*, *env*'s CA
    /// bundles and proxies, and the run's `--proxy` (*explicit_proxy*).
    pub fn new(
        label: &TenantLabel,
        settings: &HttpSettings,
        env: &Environment,
        explicit_proxy: Option<&str>,
    ) -> Result<Self, ConnectorError> {
        let setup = |message: String| ConnectorError::Setup {
            platform: label.platform.clone(),
            tenant: label.tenant.clone(),
            message,
        };
        let tls = crate::tls::client_config(&settings.tls, env).map_err(setup)?;
        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .http1_only()
            .connect_timeout(settings.timeout)
            // reqwest's read timeout runs from the start of the request, the
            // connection included, so at `timeout` it would race the connect
            // timeout and report a tenant that cannot be reached as a slow
            // one. `requests` gives the answer `timeout` once connected (at
            // most twice `timeout` from the start); the body's reads are held
            // to `timeout` each by `bytes`.
            .read_timeout(settings.timeout.saturating_mul(2))
            .no_proxy();
        for proxy in ProxySettings::from_env(env, explicit_proxy)
            .proxies()
            .map_err(setup)?
        {
            builder = builder.proxy(proxy);
        }
        let client = builder
            .build()
            .map_err(|error| setup(error::describe(error)))?;
        Ok(Self {
            client,
            label: label.clone(),
            settings: settings.clone(),
            permits: Arc::new(Semaphore::new(settings.max_in_flight.max(1))),
        })
    }

    /// The tenant this client reaches.
    pub fn label(&self) -> &TenantLabel {
        &self.label
    }

    /// The settings it was built with.
    pub fn settings(&self) -> &HttpSettings {
        &self.settings
    }

    /// A request to *url*, to finish and pass to [`HttpClient::send`].
    pub fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        self.client.request(method, url)
    }

    /// Sends *request*, retrying as the tenant's policy says, and returns
    /// the answer (an error status included: the caller reads it). Stops
    /// with [`ConnectorError::Cancelled`] when *cancel* fires.
    pub async fn send(
        &self,
        request: reqwest::Request,
        cancel: &CancellationToken,
    ) -> Result<reqwest::Response, ConnectorError> {
        let _permit = tokio::select! {
            () = cancel.cancelled() => return Err(ConnectorError::Cancelled),
            permit = self.permits.acquire() => permit.map_err(|_| ConnectorError::Cancelled)?,
        };
        let url = request.url().clone();
        let retry = &self.settings.retry;
        // urllib3 retries a status or a read timeout for the methods in its
        // list only, and a connection that could not be made for any.
        let method_retried = retry.retries(request.method().as_str());
        let mut delays = retry.delays();
        let mut pending = Some(request);
        loop {
            let Some(current) = pending.take() else {
                return Err(ConnectorError::Cancelled);
            };
            // A body that cannot be cloned (a stream) is sent once.
            let next = if retry.total > 0 {
                current.try_clone()
            } else {
                None
            };
            let outcome = tokio::select! {
                () = cancel.cancelled() => return Err(ConnectorError::Cancelled),
                outcome = self.client.execute(current) => outcome,
            };
            let wait = match &outcome {
                Ok(response)
                    if method_retried && retry.retries_status(response.status().as_u16()) =>
                {
                    let after = response
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|value| value.to_str().ok());
                    let after = retry.retry_after(response.status().as_u16(), after);
                    next.is_some()
                        .then(|| delays.next().map(|delay| after.unwrap_or(delay)))
                        .flatten()
                }
                Ok(_) => None,
                Err(failure) if failure.is_connect() => {
                    next.is_some().then(|| delays.next()).flatten()
                }
                Err(failure) if failure.is_timeout() && method_retried => {
                    next.is_some().then(|| delays.next()).flatten()
                }
                Err(_) => None,
            };
            match (wait, outcome) {
                (Some(delay), _) => {
                    tokio::select! {
                        () = cancel.cancelled() => return Err(ConnectorError::Cancelled),
                        () = tokio::time::sleep(delay) => {}
                    }
                    pending = next;
                }
                (None, Ok(response)) => return Ok(response),
                (None, Err(failure)) => {
                    return Err(error::from_reqwest(
                        failure,
                        &self.label,
                        &url,
                        self.settings.timeout.as_secs(),
                    ));
                }
            }
        }
    }

    /// Reads an answer's body, mapping a failure as [`HttpClient::send`] does;
    /// each read must bring data within the tenant's timeout (`requests`'
    /// read timeout).
    pub async fn bytes(
        &self,
        mut response: reqwest::Response,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, ConnectorError> {
        let url = response.url().clone();
        let timeout = self.settings.timeout;
        let read = async {
            let mut body = Vec::new();
            loop {
                match tokio::time::timeout(timeout, response.chunk()).await {
                    Ok(Ok(Some(chunk))) => body.extend_from_slice(&chunk),
                    Ok(Ok(None)) => return Ok(body),
                    Ok(Err(failure)) => {
                        return Err(error::from_reqwest(
                            failure,
                            &self.label,
                            &url,
                            timeout.as_secs(),
                        ));
                    }
                    Err(_) => {
                        return Err(ConnectorError::Timeout {
                            platform: self.label.platform.clone(),
                            tenant: self.label.tenant.clone(),
                            address: error::origin(&url),
                            seconds: timeout.as_secs(),
                        });
                    }
                }
            }
        };
        tokio::select! {
            () = cancel.cancelled() => Err(ConnectorError::Cancelled),
            body = read => body,
        }
    }
}
