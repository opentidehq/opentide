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
    /// What reached the tenant ([`HttpClient::requests_sent`],
    /// [`HttpClient::writes_taken`]), shared by the client's clones.
    reached: Arc<Reached>,
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
            reached: Arc::new(Reached::default()),
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

    /// How many requests left for the tenant, through this client and its
    /// clones: every attempt but one whose connection could not be made or
    /// whose certificate was refused (those were never sent).
    pub fn requests_sent(&self) -> usize {
        self.reached.sent.load(Ordering::Relaxed)
    }

    /// How many requests that may change something
    /// ([`Request::is_read_only`] is false) left for the tenant and were
    /// not refused: answered with anything but a 4xx, or not answered at
    /// all (a timeout, a connection dropped once sent), so the tenant may
    /// have taken them. While it has not grown since a tenant was opened,
    /// the tenant has taken nothing: a failure then sent no rule
    /// (`opentide deploy`'s tenant failure before any rule, #1701).
    pub fn writes_taken(&self) -> usize {
        self.reached.taken.load(Ordering::Relaxed)
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
            TransportFailure::Connect { reason }
            | TransportFailure::CertificateRefused { reason }
            | TransportFailure::Unreachable { reason } => ConnectorError::Unreachable {
                platform,
                tenant,
                address,
                reason,
            },
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
        self.send_or_unsent(request, cancel)
            .await
            .map_err(|failed| failed.error)
    }

    /// [`send`](Self::send), saying of a failure whether the request never
    /// left ([`SendFailure::unsent`]): its connection could not be made
    /// (refused, DNS, the connect timeout, a proxy that would not connect)
    /// or the tenant's certificate was refused, so the tenant did nothing
    /// with it. A connection dropped while the request was sent is not
    /// unsent: the tenant may have taken it. A platform that never sends a
    /// write twice reads it to tell an unreachable tenant from a write that
    /// may have happened.
    ///
    /// # Errors
    ///
    /// [`SendFailure`]: the [`ConnectorError`] [`send`](Self::send) returns,
    /// and whether the request was never sent.
    pub async fn send_or_unsent(
        &self,
        request: Request,
        cancel: &CancellationToken,
    ) -> Result<Response, SendFailure> {
        let failed = |error: ConnectorError| SendFailure {
            error,
            unsent: false,
        };
        // `biased`: a connection cancelled before (or while) a step is
        // ready is interrupted, never answered by whichever branch tokio
        // happens to poll first.
        let _permit = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(failed(ConnectorError::Cancelled)),
            permit = self.permits.acquire() => permit.map_err(|_| failed(ConnectorError::Cancelled))?,
        };
        let url = request.url().clone();
        let idempotent = request.is_idempotent();
        let retry = &self.settings.retry;
        // A request is cloned only for an attempt a retry may follow; the
        // last attempt takes it.
        let unsent = |failure: TransportFailure| SendFailure {
            unsent: matches!(
                failure,
                TransportFailure::Connect { .. } | TransportFailure::CertificateRefused { .. }
            ),
            error: self.error(failure, &url),
        };
        for retried in 0..retry.max_retries {
            let outcome = self
                .attempt(request.clone(), cancel)
                .await
                .map_err(failed)?;
            let Some(delay) = retry.wait_for(
                idempotent,
                retry_outcome(&outcome),
                retried,
                jiff::Timestamp::now(),
            ) else {
                return outcome.map_err(unsent);
            };
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(failed(ConnectorError::Cancelled)),
                () = tokio::time::sleep(delay) => {}
            }
        }
        self.attempt(request, cancel)
            .await
            .map_err(failed)?
            .map_err(unsent)
    }

    /// One attempt at *request*, stopped with [`ConnectorError::Cancelled`]
    /// when *cancel* fires.
    async fn attempt(
        &self,
        request: Request,
        cancel: &CancellationToken,
    ) -> Result<Result<Response, TransportFailure>, ConnectorError> {
        let write = !request.is_read_only();
        // `biased`: see `send`.
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                // Stopped while it may have been on its way: it counts.
                self.reached.note(write, true, true);
                return Err(ConnectorError::Cancelled);
            }
            outcome = self.transport.execute(request, cancel) => outcome,
        };
        let sent = !matches!(
            outcome,
            Err(TransportFailure::Connect { .. } | TransportFailure::CertificateRefused { .. })
        );
        let refused = matches!(&outcome, Ok(response) if response.status().is_client_error());
        self.reached.note(write, sent, !refused);
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

/// A request [`HttpClient::send_or_unsent`] could not complete.
#[derive(Debug)]
pub struct SendFailure {
    /// Why, as [`HttpClient::send`] says it.
    pub error: ConnectorError,
    /// The request never left: its connection could not be made, or the
    /// tenant's certificate was refused, so the tenant did nothing with it.
    pub unsent: bool,
}

/// What reached a tenant, counted by [`HttpClient::attempt`].
#[derive(Debug, Default)]
struct Reached {
    /// Requests that left.
    sent: AtomicUsize,
    /// Writes that left and were not refused.
    taken: AtomicUsize,
}

impl Reached {
    /// One attempt: a `write` or not, `sent` or never, and `not_refused`
    /// when its answer (if any) was not a 4xx.
    fn note(&self, write: bool, sent: bool, not_refused: bool) {
        if sent {
            self.sent.fetch_add(1, Ordering::Relaxed);
            if write && not_refused {
                self.taken.fetch_add(1, Ordering::Relaxed);
            }
        }
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
