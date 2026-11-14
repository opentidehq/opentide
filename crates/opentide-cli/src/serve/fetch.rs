//! `opentide/fetch`: tenant HTTP made by the client (W2,
//! `docs/engine/connector-transport.md`).
//!
//! A client that says so at `initialize` (`capabilities.fetch`) makes each
//! request a run sends to a tenant: the server asks it with an
//! `opentide/fetch` request of its own, and the client answers with the
//! tenant's answer, or with why there is none. The WASI build of opentide,
//! which VS Code's host gives no sockets, reaches tenants only this way; a
//! native server does it when asked, so the editor's HTTP stack (its proxy
//! settings, its certificate store) makes the calls.
//!
//! The requests are the server's, so their ids are strings, `"h1"`,
//! `"h2"`…, which no client id takes. A run cancelled while one is pending
//! sends `$/cancelRequest` for it and stops at once.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use base64::Engine as _;
use opentide_connectors::connector::BoxFuture;
use opentide_connectors::transport::{
    HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Transport, TransportFactory,
    TransportFailure, TransportSpec,
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::runner::compact;
use crate::json::Json;

fn int(value: &Json) -> Option<i64> {
    match value {
        Json::Int(number) => Some(*number),
        _ => None,
    }
}

fn item(value: &Json, index: usize) -> Option<&Json> {
    match value {
        Json::Array(items) => items.get(index),
        _ => None,
    }
}

/// The method of the server's request.
pub const METHOD: &str = "opentide/fetch";

/// The prefix of the server's request ids.
pub const ID_PREFIX: &str = "h";

/// How long past a tenant's own limits the server waits for the client's
/// answer before it reads the request as timed out.
const GRACE: Duration = Duration::from_secs(5);

/// What the client answered: a result, or a JSON-RPC error object.
type Reply = Result<Json, Json>;

/// The requests in flight to the client, and how to write one.
pub struct Fetcher {
    send: Box<dyn Fn(&str) + Send + Sync>,
    /// The id of the run in progress, named in each request.
    run: Box<dyn Fn() -> Option<String> + Send + Sync>,
    pending: Mutex<HashMap<String, oneshot::Sender<Reply>>>,
    next: AtomicU64,
    /// Reads the client's next message on this thread, when the server has
    /// no reading thread (the WASI build): whether one came.
    pump: Box<dyn Fn() -> bool + Send + Sync>,
    /// Whether the run in progress was cancelled.
    cancelled: Box<dyn Fn() -> bool + Send + Sync>,
}

impl std::fmt::Debug for Fetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fetcher").finish_non_exhaustive()
    }
}

impl Fetcher {
    /// A fetcher writing through *send*; *run* names the run in progress.
    pub fn new(
        send: impl Fn(&str) + Send + Sync + 'static,
        run: impl Fn() -> Option<String> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Self::with_input(send, run, || false, || false)
    }

    /// A fetcher that, while it waits for an answer, reads the client's
    /// messages itself with *pump* (`Server::pump`: the WASI build's serve
    /// loop has no reading thread), and stops waiting once *cancelled* says
    /// the run was cancelled. A *pump* that reads nothing (a server with a
    /// reading thread) leaves the answer to that thread.
    pub fn with_input(
        send: impl Fn(&str) + Send + Sync + 'static,
        run: impl Fn() -> Option<String> + Send + Sync + 'static,
        pump: impl Fn() -> bool + Send + Sync + 'static,
        cancelled: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            send: Box::new(send),
            run: Box::new(run),
            pending: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            pump: Box::new(pump),
            cancelled: Box::new(cancelled),
        })
    }

    /// Takes the client's answer to request *id*; whether it was one of ours.
    pub fn deliver(&self, id: &str, reply: Reply) -> bool {
        let waiting = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        match waiting {
            Some(sender) => {
                let _gone = sender.send(reply);
                true
            }
            None => false,
        }
    }

    /// Every request still waiting fails: the client has gone.
    pub fn close(&self) {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    fn ask(&self, params: Json) -> (String, oneshot::Receiver<Reply>) {
        let id = format!("{ID_PREFIX}{}", self.next.fetch_add(1, Ordering::SeqCst));
        let (sender, receiver) = oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.clone(), sender);
        let message = Json::object([
            ("jsonrpc", Json::str("2.0")),
            ("id", Json::str(&id)),
            ("method", Json::str(METHOD)),
            ("params", params),
        ]);
        (self.send)(&compact(&message));
        (id, receiver)
    }

    fn cancel(&self, id: &str) {
        let waiting = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        if waiting.is_some() {
            let message = Json::object([
                ("jsonrpc", Json::str("2.0")),
                ("method", Json::str("$/cancelRequest")),
                ("params", Json::object([("id", Json::str(id))])),
            ]);
            (self.send)(&compact(&message));
        }
    }
}

/// Makes each tenant's transport ask the client.
#[derive(Debug)]
pub struct ClientFetch {
    fetcher: Weak<Fetcher>,
}

impl ClientFetch {
    /// The factory of *fetcher*'s transports.
    pub fn new(fetcher: &Arc<Fetcher>) -> Arc<Self> {
        Arc::new(Self {
            fetcher: Arc::downgrade(fetcher),
        })
    }
}

impl TransportFactory for ClientFetch {
    fn make(&self, spec: &TransportSpec<'_>) -> Result<Arc<dyn Transport>, String> {
        let settings = spec.settings;
        // The tenant's own bundle must read; one the environment names is
        // skipped when it does not, as the native transport does.
        let own = settings.tls.ca_bundle.clone();
        let mut bundles = Vec::new();
        for path in opentide_connectors::tls::bundles(&settings.tls, spec.env) {
            match std::fs::read_to_string(&path) {
                Ok(text) => bundles.push(Json::Str(text)),
                Err(error) if own.as_ref() == Some(&path) => {
                    return Err(format!(
                        "cannot read the CA bundle {}: {error}",
                        path.display()
                    ));
                }
                Err(_) => {}
            }
        }
        Ok(Arc::new(ClientTransport {
            fetcher: self.fetcher.clone(),
            platform: spec.label.platform.clone(),
            tenant: spec.label.tenant.clone(),
            verify: settings.tls.verify,
            bundles,
            proxies: spec.proxies.clone(),
            timeout: settings.timeout,
        }))
    }
}

/// One tenant's transport through the client.
#[derive(Debug)]
struct ClientTransport {
    fetcher: Weak<Fetcher>,
    platform: String,
    tenant: String,
    verify: bool,
    bundles: Vec<Json>,
    proxies: opentide_connectors::proxy::ProxySettings,
    timeout: Duration,
}

impl ClientTransport {
    fn params(&self, request: &Request, fetcher: &Fetcher) -> Json {
        let millis =
            |duration: Duration| Json::Int(i64::try_from(duration.as_millis()).unwrap_or(i64::MAX));
        let headers = request
            .headers()
            .iter()
            .map(|(name, value)| {
                Json::Array(vec![
                    Json::str(name.as_str()),
                    Json::Str(String::from_utf8_lossy(value.as_bytes()).into_owned()),
                ])
            })
            .collect();
        let body = request.body().map_or(Json::Null, |body| {
            Json::Str(base64::engine::general_purpose::STANDARD.encode(body))
        });
        let proxy = self
            .proxies
            .proxy_for(request.url())
            .map_or(Json::Null, Json::Str);
        Json::object([
            ("run", (fetcher.run)().map_or(Json::Null, Json::Str)),
            ("platform", Json::str(&self.platform)),
            ("tenant", Json::str(&self.tenant)),
            ("method", Json::str(request.method().as_str())),
            ("url", Json::str(request.url().as_str())),
            ("headers", Json::Array(headers)),
            ("body", body),
            ("connect_timeout_ms", millis(self.timeout)),
            (
                "read_timeout_ms",
                millis(request.timeout().unwrap_or(self.timeout)),
            ),
            (
                "tls",
                Json::object([
                    ("verify", Json::Bool(self.verify)),
                    ("ca_bundles", Json::Array(self.bundles.clone())),
                ]),
            ),
            ("proxy", proxy),
        ])
    }
}

/// The failure a client's error object names (`data.kind`).
fn failure(error: &Json) -> TransportFailure {
    let message = error
        .get("message")
        .and_then(Json::as_str)
        .unwrap_or("the client could not make the request")
        .to_owned();
    let kind = error
        .get("data")
        .and_then(|data| data.get("kind"))
        .and_then(Json::as_str)
        .unwrap_or_default();
    match kind {
        "connect" => TransportFailure::Connect { reason: message },
        "timeout" => TransportFailure::Timeout,
        "aborted" => TransportFailure::Cancelled,
        "answer" | "body" => TransportFailure::Answer { reason: message },
        _ => TransportFailure::Unreachable { reason: message },
    }
}

/// The tenant's answer in a client's result, or why it does not read.
fn response(
    result: &Json,
    request_url: &url::Url,
    measured: Duration,
) -> Result<Response, TransportFailure> {
    let unreadable = |what: &str| TransportFailure::Answer {
        reason: format!("the client's answer to {METHOD} has no valid {what}"),
    };
    let status = result
        .get("status")
        .and_then(int)
        .and_then(|status| u16::try_from(status).ok())
        .and_then(|status| StatusCode::from_u16(status).ok())
        .ok_or_else(|| unreadable("status"))?;
    let mut headers = HeaderMap::new();
    if let Some(Json::Array(pairs)) = result.get("headers") {
        for pair in pairs {
            let (Some(name), Some(value)) = (
                item(pair, 0).and_then(Json::as_str),
                item(pair, 1).and_then(Json::as_str),
            ) else {
                return Err(unreadable("headers"));
            };
            let name =
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| unreadable("headers"))?;
            let value = HeaderValue::from_str(value).map_err(|_| unreadable("headers"))?;
            headers.append(name, value);
        }
    }
    let url = match result.get("url").and_then(Json::as_str) {
        Some(url) => url::Url::parse(url).map_err(|_| unreadable("url"))?,
        None => request_url.clone(),
    };
    let body = match result.get("body") {
        None | Some(Json::Null) => Vec::new(),
        Some(Json::Str(text)) => base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(|_| unreadable("body"))?,
        Some(_) => return Err(unreadable("body")),
    };
    let elapsed = result
        .get("elapsed_ms")
        .and_then(int)
        .and_then(|millis| u64::try_from(millis).ok())
        .map_or(measured, Duration::from_millis);
    Ok(Response::new(
        status,
        headers,
        url,
        (elapsed, Duration::ZERO),
        Ok(body),
    ))
}

/// A request to the client not answered yet: withdrawn (`$/cancelRequest`)
/// when dropped before its answer came.
struct Pending<'a> {
    fetcher: &'a Fetcher,
    id: &'a str,
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        // A no-op once the answer was delivered: it is no longer pending.
        self.fetcher.cancel(self.id);
    }
}

impl Transport for ClientTransport {
    fn execute<'a>(
        &'a self,
        request: Request,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Response, TransportFailure>> {
        Box::pin(async move {
            let Some(fetcher) = self.fetcher.upgrade() else {
                return Err(TransportFailure::Unreachable {
                    reason: "the client that made the tenant's requests has gone".to_owned(),
                });
            };
            let started = std::time::Instant::now();
            let url = request.url().clone();
            let read = request.timeout().unwrap_or(self.timeout);
            let (id, reply) = fetcher.ask(self.params(&request, &fetcher));
            // Withdrawn however the wait ends early: the run cancelled, the
            // limit passed, or this future dropped (a run that stops by
            // dropping its work).
            let pending = Pending {
                fetcher: &fetcher,
                id: &id,
            };
            // With no reading thread, the answer comes only as this thread
            // reads it: pump the client's messages until it is taken. Each
            // message is handled as the reading thread would handle it (a
            // cancel reaches the run), so the run's cancellation is checked
            // after each: the command's own watch cannot run meanwhile.
            let mut reply = reply;
            loop {
                match reply.try_recv() {
                    Ok(answer) => {
                        drop(pending);
                        return match answer {
                            Err(error) => Err(failure(&error)),
                            Ok(result) => response(&result, &url, started.elapsed()),
                        };
                    }
                    Err(oneshot::error::TryRecvError::Closed) => {
                        drop(pending);
                        return Err(TransportFailure::Unreachable {
                            reason: "the client that made the tenant's requests has gone"
                                .to_owned(),
                        });
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {}
                }
                if cancel.is_cancelled() || (fetcher.cancelled)() {
                    return Err(TransportFailure::Cancelled);
                }
                if !(fetcher.pump)() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            let limit = self.timeout + read + GRACE;
            let outcome = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(TransportFailure::Cancelled),
                outcome = tokio::time::timeout(limit, reply) => outcome,
            };
            drop(pending);
            match outcome {
                Err(_) => Err(TransportFailure::Timeout),
                Ok(Err(_)) => Err(TransportFailure::Unreachable {
                    reason: "the client that made the tenant's requests has gone".to_owned(),
                }),
                Ok(Ok(Err(error))) => Err(failure(&error)),
                Ok(Ok(Ok(result))) => response(&result, &url, started.elapsed()),
            }
        })
    }
}
