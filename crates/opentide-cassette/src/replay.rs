//! Replaying a cassette with wiremock: each recorded answer is served to the
//! request in its place, in order, and [`Replay::verify`] then asserts that
//! the requests received are the recorded ones, byte for byte once
//! normalised ([`crate::redact`]), in the same order.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

use crate::cassette::{self, Body, Cassette, Interaction};
use crate::redact::Redaction;

/// The status a request gets when it is not the one the cassette expects
/// next, so the client fails rather than reading a wrong answer.
pub const MISMATCH_STATUS: u16 = 599;

/// A cassette served by a wiremock server.
pub struct Replay {
    server: MockServer,
    cassette: Cassette,
    redaction: Redaction,
    origin: Option<String>,
}

impl std::fmt::Debug for Replay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replay")
            .field("uri", &self.server.uri())
            .field("scenario", &self.cassette.scenario)
            .finish_non_exhaustive()
    }
}

/// The request wiremock received, as a cassette request: its origin is the
/// one the proxy names in [`crate::ORIGIN_HEADER`], else *origin* (a client
/// pointed at the replay server itself), else the server's own.
pub fn received(
    request: &wiremock::Request,
    origin: Option<&str>,
    redaction: &Redaction,
) -> cassette::Request {
    let header_origin = request
        .headers
        .get(crate::ORIGIN_HEADER)
        .and_then(|value| value.to_str().ok());
    let base = header_origin.or(origin).map_or_else(
        || {
            let url = &request.url;
            crate::origin(url)
        },
        str::to_owned,
    );
    let mut path = request.url.path().to_owned();
    if let Some(query) = request.url.query() {
        path.push('?');
        path.push_str(query);
    }
    let headers = request
        .headers
        .iter()
        .filter_map(|(name, value)| Some((name.as_str(), value.to_str().ok()?)));
    cassette::Request {
        method: request.method.as_str().to_owned(),
        url: redaction.url(&format!("{base}{path}")),
        headers: redaction.request_headers(headers),
        body: Body::from_bytes(&redaction.body(&request.body)),
    }
}

/// Serves interaction *index* when it is the next one due and the request
/// is the recorded one.
struct InOrder {
    index: usize,
    expected: cassette::Request,
    answer: cassette::Response,
    next: Arc<AtomicUsize>,
    redaction: Redaction,
    origin: Option<String>,
}

impl wiremock::Match for InOrder {
    fn matches(&self, request: &wiremock::Request) -> bool {
        self.next.load(Ordering::SeqCst) == self.index
            && received(request, self.origin.as_deref(), &self.redaction) == self.expected
    }
}

impl Respond for InOrder {
    fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
        self.next.fetch_add(1, Ordering::SeqCst);
        let mut template = ResponseTemplate::new(self.answer.status);
        for (name, value) in &self.answer.headers {
            template = template.append_header(name.as_str(), value.as_str());
        }
        template.set_body_bytes(self.answer.body.bytes())
    }
}

/// What a request was compared with, when it differed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    /// The request's place in the run (0-based).
    pub index: usize,
    /// What differs.
    pub detail: String,
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request {}: {}", self.index + 1, self.detail)
    }
}

impl Replay {
    /// Serves *cassette*. *origin* is the origin a client pointed straight
    /// at the server stands for (`https://tenant.example`); `None` when the
    /// replay proxy sits in front and names it.
    pub async fn start(cassette: Cassette, redaction: Redaction, origin: Option<String>) -> Self {
        let server = MockServer::builder().start().await;
        let next = Arc::new(AtomicUsize::new(0));
        for (index, Interaction { request, response }) in
            cassette.interactions.iter().cloned().enumerate()
        {
            let rule = InOrder {
                index,
                expected: request,
                answer: response.clone(),
                next: next.clone(),
                redaction: redaction.clone(),
                origin: origin.clone(),
            };
            let responder = InOrder {
                index,
                expected: rule.expected.clone(),
                answer: response,
                next: next.clone(),
                redaction: redaction.clone(),
                origin: origin.clone(),
            };
            Mock::given(rule)
                .respond_with(responder)
                .up_to_n_times(1)
                .with_priority(1)
                .mount(&server)
                .await;
        }
        Mock::given(wiremock::matchers::any())
            .respond_with(
                ResponseTemplate::new(MISMATCH_STATUS)
                    .set_body_string("not the request the cassette expects here"),
            )
            .with_priority(u8::MAX)
            .mount(&server)
            .await;
        Self {
            server,
            cassette,
            redaction,
            origin,
        }
    }

    /// The server's base URL (`http://127.0.0.1:<port>`).
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// The requests received, normalised.
    pub async fn requests(&self) -> Vec<cassette::Request> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|request| received(request, self.origin.as_deref(), &self.redaction))
            .collect()
    }

    /// Every difference between the requests received and the cassette's.
    pub async fn verify(&self) -> Vec<Mismatch> {
        let expected: Vec<&cassette::Request> = self
            .cassette
            .interactions
            .iter()
            .map(|interaction| &interaction.request)
            .collect();
        compare(&expected, &self.requests().await)
    }
}

/// Every difference between *expected* and *actual*, in order.
pub fn compare(expected: &[&cassette::Request], actual: &[cassette::Request]) -> Vec<Mismatch> {
    let mut mismatches = Vec::new();
    for index in 0..expected.len().max(actual.len()) {
        let detail = match (expected.get(index), actual.get(index)) {
            (Some(want), Some(got)) => differences(want, got),
            (Some(want), None) => Some(format!(
                "{} {} was recorded and never sent",
                want.method, want.url
            )),
            (None, Some(got)) => Some(format!(
                "{} {} was sent and is not in the cassette",
                got.method, got.url
            )),
            (None, None) => None,
        };
        if let Some(detail) = detail {
            mismatches.push(Mismatch { index, detail });
        }
    }
    mismatches
}

/// What differs between two requests, the first field that does.
fn differences(want: &cassette::Request, got: &cassette::Request) -> Option<String> {
    if want.method != got.method {
        return Some(format!(
            "method {} was recorded, {} sent",
            want.method, got.method
        ));
    }
    if want.url != got.url {
        return Some(format!("URL {} was recorded, {} sent", want.url, got.url));
    }
    if want.headers != got.headers {
        return Some(format!(
            "headers {:?} were recorded, {:?} sent",
            want.headers, got.headers
        ));
    }
    let (want_body, got_body) = (want.body.bytes(), got.body.bytes());
    if want_body != got_body {
        let at = want_body
            .iter()
            .zip(&got_body)
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| want_body.len().min(got_body.len()));
        return Some(format!(
            "bodies differ at byte {at}: recorded {:?}, sent {:?}",
            String::from_utf8_lossy(&want_body),
            String::from_utf8_lossy(&got_body)
        ));
    }
    None
}
