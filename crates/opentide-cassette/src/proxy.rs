//! The recording and replaying proxy.
//!
//! The client under test (the Python oracle, or the Rust CLI) runs with
//! `HTTPS_PROXY` and `HTTP_PROXY` pointing here and trusts this run's CA
//! ([`crate::tls::TestCa`], through `SSL_CERT_FILE` and
//! `REQUESTS_CA_BUNDLE`). For an `https://` URL the client opens a tunnel
//! (`CONNECT host:443`); the proxy answers it with a certificate for that
//! host and reads the requests inside. Then:
//!
//! - [`Mode::Record`] forwards each request to the real host, through the
//!   environment's own proxy and CA, or to a local stand-in the scenario
//!   routes the host to, and records it with its answer, normalised and
//!   redacted ([`crate::redact`]);
//! - [`Mode::Replay`] hands it to a [`Replay`] (wiremock), which serves the
//!   cassette's answers in order and checks the requests.
//!
//! The proxy is the recording mechanism for every client: `requests`,
//! `urllib` and reqwest alike, with nothing patched inside the client.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::cassette::{self, Body, Cassette, Interaction};
use crate::redact::Redaction;
use crate::replay::{Mismatch, Replay};
use crate::tls::TestCa;

/// What the proxy does with a request.
#[derive(Debug)]
pub enum Mode {
    /// Forward and record. `routes` sends a host (`tenant.invalid`, or
    /// `host:port`) to a local stand-in (`http://127.0.0.1:8123`) instead of
    /// the network.
    Record {
        /// Hosts answered by a local stand-in.
        routes: BTreeMap<String, String>,
    },
    /// Serve *cassette* and check the requests.
    Replay {
        /// The cassette.
        cassette: Cassette,
    },
}

/// What the connections share.
struct Shared {
    ca: TestCa,
    redaction: Redaction,
    routes: BTreeMap<String, String>,
    replay: Option<Replay>,
    recorded: Mutex<Vec<Interaction>>,
    network: reqwest::Client,
    direct: reqwest::Client,
}

/// A running proxy. Dropping it stops it.
pub struct Proxy {
    runtime: Option<tokio::runtime::Runtime>,
    addr: SocketAddr,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// rustls on ring, trusting the system's certificates (`SSL_CERT_FILE`
/// included, which rustls-native-certs reads).
fn tls_config() -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| error.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

/// The forwarding client to the network: the environment's proxy and the
/// system's certificates (with `SSL_CERT_FILE`).
fn network_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls_config()?)
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())
}

/// The forwarding client to a local stand-in or the replay server.
fn direct_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls_config()?)
        .no_proxy()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())
}

impl Proxy {
    /// Starts a proxy on a loopback port, on a runtime of its own. Call it
    /// outside any tokio runtime.
    pub fn start(mode: Mode, redaction: Redaction) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        let (routes, replay) = match mode {
            Mode::Record { routes } => (routes, None),
            Mode::Replay { cassette } => (
                BTreeMap::new(),
                Some(runtime.block_on(Replay::start(cassette, redaction.clone(), None))),
            ),
        };
        let shared = Arc::new(Shared {
            ca: TestCa::new()?,
            redaction,
            routes,
            replay,
            recorded: Mutex::new(Vec::new()),
            network: network_client()?,
            direct: direct_client()?,
        });
        let listener = runtime
            .block_on(TcpListener::bind("127.0.0.1:0"))
            .map_err(|error| error.to_string())?;
        let addr = listener.local_addr().map_err(|error| error.to_string())?;
        let accepting = shared.clone();
        runtime.spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let shared = accepting.clone();
                tokio::spawn(async move {
                    let _ = connection(stream, shared).await;
                });
            }
        });
        Ok(Self {
            runtime: Some(runtime),
            addr,
            shared,
        })
    }

    /// `http://127.0.0.1:<port>`, for `HTTPS_PROXY` and `HTTP_PROXY`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The run's CA certificate (PEM), for the client's CA bundle.
    pub fn ca_pem(&self) -> &str {
        self.shared.ca.pem()
    }

    /// What was recorded so far, in order.
    pub fn interactions(&self) -> Vec<Interaction> {
        self.shared
            .recorded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// In replay, every difference between what was sent and the cassette.
    pub fn verify(&self) -> Vec<Mismatch> {
        match (&self.shared.replay, &self.runtime) {
            (Some(replay), Some(runtime)) => runtime.block_on(replay.verify()),
            _ => Vec::new(),
        }
    }

    /// The environment a client under test runs with: every proxy variable
    /// pointing here, no `NO_PROXY`, and *ca_file* (where the caller wrote
    /// [`Proxy::ca_pem`]) as its CA bundle.
    pub fn client_env(&self, ca_file: &str) -> Vec<(String, String)> {
        let url = self.url();
        let mut env: Vec<(String, String)> = [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ]
        .iter()
        .map(|name| ((*name).to_owned(), url.clone()))
        .collect();
        for name in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"] {
            env.push((name.to_owned(), ca_file.to_owned()));
        }
        env
    }
}

/// One client connection: a tunnel or a plain proxied request.
async fn connection(mut stream: TcpStream, shared: Arc<Shared>) -> Result<(), String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 65_536 || stream.read(&mut byte).await.map_err(|e| e.to_string())? == 0 {
            return Ok(());
        }
        head.push(byte[0]);
    }
    let line = String::from_utf8_lossy(&head);
    let mut words = line.split_whitespace();
    let method = words.next().unwrap_or_default().to_owned();
    let target = words.next().unwrap_or_default().to_owned();
    if method.eq_ignore_ascii_case("CONNECT") {
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|error| error.to_string())?;
        let (host, port) = target
            .rsplit_once(':')
            .map_or((target.as_str(), "443"), |(host, port)| (host, port));
        let config = shared.ca.server_config(host)?;
        let tls = tokio_rustls::TlsAcceptor::from(config)
            .accept(stream)
            .await
            .map_err(|error| error.to_string())?;
        let origin = if port == "443" {
            format!("https://{host}")
        } else {
            format!("https://{host}:{port}")
        };
        serve(TokioIo::new(tls), shared, Some(origin)).await
    } else {
        let stream = Prefixed {
            prefix: head,
            at: 0,
            inner: stream,
        };
        serve(TokioIo::new(stream), shared, None).await
    }
}

/// Serves HTTP/1.1 on *io*: the requests of one tunnel to *origin*, or
/// proxied requests in absolute form.
async fn serve<I>(io: TokioIo<I>, shared: Arc<Shared>, origin: Option<String>) -> Result<(), String>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        let shared = shared.clone();
        let origin = origin.clone();
        async move { Ok::<_, std::convert::Infallible>(handle(request, &shared, origin).await) }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .await
        .map_err(|error| error.to_string())
}

/// A failure the proxy answers itself.
fn failure(status: u16, message: &str) -> hyper::Response<Full<Bytes>> {
    let mut response = hyper::Response::new(Full::new(Bytes::from(message.to_owned())));
    *response.status_mut() =
        hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::BAD_GATEWAY);
    response
}

/// One request: forwarded, recorded or replayed.
async fn handle(
    request: hyper::Request<hyper::body::Incoming>,
    shared: &Shared,
    origin: Option<String>,
) -> hyper::Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    let Ok(body) = body.collect().await.map(|collected| collected.to_bytes()) else {
        return failure(502, "the request's body could not be read");
    };
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    let url = match &origin {
        Some(origin) => format!("{origin}{path}"),
        None => parts.uri.to_string(),
    };
    let Ok(parsed) = url::Url::parse(&url) else {
        return failure(400, "not a URL");
    };
    let request_origin = crate::origin(&parsed);
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
        })
        .collect();
    let (client, target, extra) = if let Some(replay) = &shared.replay {
        (
            &shared.direct,
            format!("{}{path}", replay.uri()),
            Some(request_origin.clone()),
        )
    } else if let Some(route) = route(&shared.routes, &parsed) {
        (&shared.direct, format!("{route}{path}"), None)
    } else {
        (&shared.network, url.clone(), None)
    };
    let Ok(method) = reqwest::Method::from_bytes(parts.method.as_str().as_bytes()) else {
        return failure(400, "not a method");
    };
    let mut forward = client.request(method, &target);
    for (name, value) in &headers {
        let lowered = name.to_ascii_lowercase();
        if matches!(
            lowered.as_str(),
            "host"
                | "connection"
                | "proxy-connection"
                | "proxy-authorization"
                | "keep-alive"
                | "content-length"
                | "transfer-encoding"
        ) {
            continue;
        }
        forward = forward.header(name.as_str(), value.as_str());
    }
    if let Some(origin) = extra {
        forward = forward.header(crate::ORIGIN_HEADER, origin);
    }
    let answer = match forward.body(body.to_vec()).send().await {
        Ok(answer) => answer,
        Err(error) => return failure(502, &format!("upstream: {}", error.without_url())),
    };
    let status = answer.status().as_u16();
    let answer_headers: Vec<(String, String)> = answer
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
        })
        .collect();
    let Ok(answer_body) = answer.bytes().await else {
        return failure(502, "the answer's body could not be read");
    };
    if shared.replay.is_none() {
        let redaction = &shared.redaction;
        let interaction = Interaction {
            request: cassette::Request {
                method: parts.method.as_str().to_owned(),
                url: redaction.url(&url),
                headers: redaction
                    .request_headers(headers.iter().map(|(n, v)| (n.as_str(), v.as_str()))),
                body: Body::from_bytes(&redaction.body(&body)),
            },
            response: cassette::Response {
                status,
                headers: redaction
                    .response_headers(answer_headers.iter().map(|(n, v)| (n.as_str(), v.as_str()))),
                body: Body::from_bytes(&redaction.body(&answer_body)),
            },
        };
        shared
            .recorded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(interaction);
    }
    let mut response = hyper::Response::new(Full::new(answer_body));
    *response.status_mut() =
        hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::BAD_GATEWAY);
    for (name, value) in answer_headers {
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "connection" | "transfer-encoding" | "content-length" | "keep-alive"
        ) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            hyper::header::HeaderName::from_bytes(name.as_bytes()),
            hyper::header::HeaderValue::from_str(&value),
        ) {
            response.headers_mut().append(name, value);
        }
    }
    response
}

/// The stand-in a scenario routes *url*'s host to.
fn route<'a>(routes: &'a BTreeMap<String, String>, url: &url::Url) -> Option<&'a str> {
    let host = url.host_str()?;
    let with_port = url.port().map(|port| format!("{host}:{port}"));
    with_port
        .and_then(|key| routes.get(&key))
        .or_else(|| routes.get(host))
        .map(|base| base.trim_end_matches('/'))
}

/// A stream that first yields bytes already read from it.
struct Prefixed {
    prefix: Vec<u8>,
    at: usize,
    inner: TcpStream,
}

impl AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.at < self.prefix.len() {
            let rest = &self.prefix[self.at..];
            let count = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..count]);
            self.at += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
