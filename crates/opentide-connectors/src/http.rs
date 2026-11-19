//! The HTTP client of one tenant: `TenantSession` in Rust.
//!
//! One [`HttpClient`] per tenant, built from that tenant's [`HttpSettings`]
//! and the run's environment: TLS on or off and the CA bundles it trusts
//! ([`crate::tls`]), the proxy ([`crate::proxy`]), a timeout on connecting
//! and on each read of the answer (120 s when a platform names none:
//! [`DEFAULT_TIMEOUT`]), the retries ([`crate::retry`]) and how many requests
//! may be in flight to it at once. HTTP/2 when the tenant offers it, else
//! HTTP/1.1; no default `User-Agent`, compression or redirects beyond
//! reqwest's.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::error::{self, ConnectorError};
use crate::proxy::ProxySettings;
use crate::retry::{Outcome, RetryPolicy};
use crate::tls::TlsSettings;
use crate::transport::{
    self, Method, Request, RequestBuilder, Response, Transport, TransportFailure, TransportSpec,
};
use crate::{Environment, TenantLabel};

/// How long a tenant has to accept a connection and then to send each
/// part of its answer, when a platform names none.
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
    transport: Arc<dyn Transport>,
    label: TenantLabel,
    settings: HttpSettings,
    permits: Arc<Semaphore>,
    proxies: ProxySettings,
    /// The writes the tenant accepted ([`HttpClient::writes_accepted`]),
    /// shared by the client's clones.
    accepted: Arc<AtomicUsize>,
}

impl HttpClient {
    /// The client of the tenant *label*, from its *settings*, *env*'s CA
    /// bundles and proxies, and the run's `--proxy` (*explicit_proxy*), on
    /// the build's transport or the one the run installed
    /// ([`crate::transport::install`]).
    pub fn new(
        label: &TenantLabel,
        settings: &HttpSettings,
        env: &Environment,
        explicit_proxy: Option<&str>,
    ) -> Result<Self, ConnectorError> {
        let proxies = ProxySettings::from_env(env, explicit_proxy);
        let transport = transport::make(&TransportSpec {
            label,
            settings,
            proxies: &proxies,
            env,
        })
        .map_err(|error| match error {
            transport::MakeError::Setup(message) => ConnectorError::Setup {
                platform: label.platform.clone(),
                tenant: label.tenant.clone(),
                message,
            },
            transport::MakeError::NetworkUnavailable => ConnectorError::NetworkUnavailable {
                platform: label.platform.clone(),
                tenant: label.tenant.clone(),
            },
        })?;
        Ok(Self {
            transport,
            label: label.clone(),
            settings: settings.clone(),
            permits: Arc::new(Semaphore::new(settings.max_in_flight.max(1))),
            proxies,
            accepted: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// The proxy a request to *url* goes through, as `scheme://host[:port]`
    /// without credentials; `None` when it goes direct (`splunk_route`).
    pub fn route(&self, url: &url::Url) -> Option<String> {
        self.proxies.route(url)
    }

    /// The tenant this client reaches.
    pub fn label(&self) -> &TenantLabel {
        &self.label
    }

    /// The settings it was built with.
    pub fn settings(&self) -> &HttpSettings {
        &self.settings
    }

    /// How many requests that may change something (any method but `GET`,
    /// `HEAD` and `OPTIONS`) the tenant answered with a 2xx status, through
    /// this client and its clones. While it has not grown since a tenant
    /// was opened, the tenant has taken nothing: a failure then sent no
    /// rule (`opentide deploy`'s tenant failure before any rule, #1701).
    pub fn writes_accepted(&self) -> usize {
        self.accepted.load(Ordering::Relaxed)
    }

    /// A request to *url*, to finish and pass to [`HttpClient::send`].
    pub fn request(&self, method: Method, url: &str) -> RequestBuilder {
        RequestBuilder::new(method, url)
    }

    /// The failure *failure* of a request to *url*, naming this tenant.
    fn error(&self, failure: TransportFailure, url: &url::Url) -> ConnectorError {
        let platform = self.label.platform.clone();
        let tenant = self.label.tenant.clone();
        let address = error::origin(url);
        match failure {
            TransportFailure::Connect { reason } | TransportFailure::Unreachable { reason } => {
                ConnectorError::Unreachable {
                    platform,
                    tenant,
                    address,
                    reason,
                }
            }
            TransportFailure::Timeout => ConnectorError::Timeout {
                platform,
                tenant,
                address,
                seconds: self.settings.timeout.as_secs(),
            },
            TransportFailure::Answer { reason } => ConnectorError::Answer {
                platform,
                tenant,
                address,
                reason,
            },
            TransportFailure::Cancelled => ConnectorError::Cancelled,
        }
    }

    /// Sends *request*, retrying as the tenant's [`RetryPolicy`] says, and
    /// returns the answer (an error status included, the last one when the
    /// retries ran out: the caller reads it). Stops
    /// with [`ConnectorError::Cancelled`] when *cancel* fires.
    pub async fn send(
        &self,
        request: Request,
        cancel: &CancellationToken,
    ) -> Result<Response, ConnectorError> {
        // `biased`: a connection cancelled before (or while) a step is
        // ready is interrupted, never answered by whichever branch tokio
        // happens to poll first.
        let _permit = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(ConnectorError::Cancelled),
            permit = self.permits.acquire() => permit.map_err(|_| ConnectorError::Cancelled)?,
        };
        let url = request.url().clone();
        let idempotent = request.is_idempotent();
        let retry = &self.settings.retry;
        // A request is cloned only for an attempt a retry may follow; the
        // last attempt takes it.
        for retried in 0..retry.max_retries {
            let outcome = self.attempt(request.clone(), cancel).await?;
            let Some(delay) = retry.wait_for(
                idempotent,
                retry_outcome(&outcome),
                retried,
                jiff::Timestamp::now(),
            ) else {
                return outcome.map_err(|failure| self.error(failure, &url));
            };
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(ConnectorError::Cancelled),
                () = tokio::time::sleep(delay) => {}
            }
        }
        self.attempt(request, cancel)
            .await?
            .map_err(|failure| self.error(failure, &url))
    }

    /// One attempt at *request*, stopped with [`ConnectorError::Cancelled`]
    /// when *cancel* fires.
    async fn attempt(
        &self,
        request: Request,
        cancel: &CancellationToken,
    ) -> Result<Result<Response, TransportFailure>, ConnectorError> {
        let write = !matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        );
        // `biased`: see `send`.
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(ConnectorError::Cancelled),
            outcome = self.transport.execute(request, cancel) => outcome,
        };
        if write && matches!(&outcome, Ok(response) if response.status().is_success()) {
            self.accepted.fetch_add(1, Ordering::Relaxed);
        }
        Ok(outcome)
    }

    /// An answer's body, read whole by the transport, or why it could not
    /// be read: each read must have brought data within the tenant's
    /// timeout (`requests`' read timeout).
    #[expect(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "async as it was when it read the body: every caller awaits it, and a \
                  transport may read lazily again"
    )]
    pub async fn bytes(
        &self,
        response: Response,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, ConnectorError> {
        if cancel.is_cancelled() {
            return Err(ConnectorError::Cancelled);
        }
        let url = response.url().clone();
        response
            .into_body()
            .map_err(|failure| self.error(failure, &url))
    }
}

/// What a retry policy reads of an attempt.
fn retry_outcome(outcome: &Result<Response, TransportFailure>) -> Outcome<'_> {
    match outcome {
        Ok(response) => Outcome::Answer {
            status: response.status(),
            retry_after: response
                .headers()
                .get(http::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
        },
        Err(TransportFailure::Connect { .. }) => Outcome::NotSent,
        Err(_) => Outcome::Failed,
    }
}
