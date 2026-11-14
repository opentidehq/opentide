//! Replaying a cassette with wiremock: each recorded answer is served to the
//! request in its place, in order, and [`Replay::verify`] then asserts that
//! the requests received are the recorded ones once normalised
//! ([`crate::redact`]), in the same order.
//!
//! Requests are compared for what they mean, not for the bytes one HTTP
//! library writes:
//!
//! - **Method**: the same.
//! - **URL** ([`same_url`]): the same scheme, user info, host, port and
//!   fragment; the same path segments once percent-decoded (`%7E` is `~`,
//!   `%2f` is `%2F`; an encoded `/` stays inside its segment); the same
//!   query parameters once decoded as `application/x-www-form-urlencoded`
//!   (`+` and `%20` are both a space), names in any order, a repeated name's
//!   values in the order sent.
//! - **Headers**: the same set, after [`crate::redact`] and leaving out
//!   [`IDENTITY_HEADERS`] on both sides, the headers in which a client library
//!   names itself or its telemetry and stamps a fresh correlation id.
//!   Authorization, content type, `Accept` and every other header are
//!   compared by value.
//! - **Body**: a form body (the recorded request's `Content-Type` is
//!   `application/x-www-form-urlencoded`) as its decoded fields
//!   ([`same_form`]), as the query; a JSON body as the same data
//!   ([`same_body`]): key order, spacing and escapes are layout; any other
//!   body byte for byte.
//! - **Order**: the requests in the order recorded.
//!
//! A cassette replays as many times as it is run through: after its last
//! interaction the next request is compared with its first. Each pass must
//! be whole: a test that runs a command twice must send the scenario's
//! requests each time.

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
    len: usize,
    expected: cassette::Request,
    answer: cassette::Response,
    next: Arc<AtomicUsize>,
    redaction: Redaction,
    origin: Option<String>,
}

impl wiremock::Match for InOrder {
    fn matches(&self, request: &wiremock::Request) -> bool {
        self.next.load(Ordering::SeqCst) % self.len == self.index
            && differences(
                &self.expected,
                &received(request, self.origin.as_deref(), &self.redaction),
            )
            .is_none()
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
        let len = cassette.interactions.len().max(1);
        for (index, Interaction { request, response }) in
            cassette.interactions.iter().cloned().enumerate()
        {
            let rule = InOrder {
                index,
                len,
                expected: request,
                answer: response.clone(),
                next: next.clone(),
                redaction: redaction.clone(),
                origin: origin.clone(),
            };
            let responder = InOrder {
                index,
                len,
                expected: rule.expected.clone(),
                answer: response,
                next: next.clone(),
                redaction: redaction.clone(),
                origin: origin.clone(),
            };
            Mock::given(rule)
                .respond_with(responder)
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

    /// Every difference between the requests received and the cassette's,
    /// played as many whole times as the requests need (at least once).
    pub async fn verify(&self) -> Vec<Mismatch> {
        let received = self.requests().await;
        let len = self.cassette.interactions.len().max(1);
        let passes = received.len().div_ceil(len).max(1);
        let expected: Vec<&cassette::Request> = self
            .cassette
            .interactions
            .iter()
            .map(|interaction| &interaction.request)
            .cycle()
            .take(self.cassette.interactions.len() * passes)
            .collect();
        compare(&expected, &received)
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
    if !same_url(&want.url, &got.url) {
        return Some(format!("URL {} was recorded, {} sent", want.url, got.url));
    }
    let (want_headers, got_headers) = (meaningful(&want.headers), meaningful(&got.headers));
    if want_headers != got_headers {
        return Some(format!(
            "headers {want_headers:?} were recorded, {got_headers:?} sent"
        ));
    }
    let (want_body, got_body) = (want.body.bytes(), got.body.bytes());
    let same = if is_form(&want.headers) {
        same_form(&want_body, &got_body)
    } else {
        same_body(&want_body, &got_body)
    };
    if !same {
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

/// Request headers a client library adds to name itself, report its
/// telemetry or correlate one request in its logs: MSAL's `x-client-*` and
/// `x-ms-lib-capability`, the request ids of MSAL and azure-core. They carry
/// no meaning for the platform, each library writes its own (a fresh id per
/// request), so the matcher leaves them out on both sides. Only such headers
/// belong here: never one that authenticates, negotiates content or selects
/// an API version.
pub const IDENTITY_HEADERS: [&str; 10] = [
    "client-request-id",
    "return-client-request-id",
    "x-ms-client-request-id",
    "x-client-sku",
    "x-client-ver",
    "x-client-os",
    "x-client-cpu",
    "x-client-current-telemetry",
    "x-client-last-telemetry",
    "x-ms-lib-capability",
];

/// *headers* (names in lower case, as recorded) without [`IDENTITY_HEADERS`].
fn meaningful(headers: &[(String, String)]) -> Vec<&(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| !IDENTITY_HEADERS.contains(&name.as_str()))
        .collect()
}

/// The form media type.
const FORM: &str = "application/x-www-form-urlencoded";

/// Whether *headers* say the body is [`FORM`].
fn is_form(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name == "content-type"
            && value
                .split(';')
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case(FORM))
    })
}

/// Whether a URL sent names what the recorded one does: the same scheme,
/// user info, host, port and fragment, the same percent-decoded path
/// segments and the same decoded query parameters ([`same_form`]). Two
/// texts that are not both URLs match only when equal.
pub fn same_url(want: &str, got: &str) -> bool {
    if want == got {
        return true;
    }
    let (Ok(want), Ok(got)) = (url::Url::parse(want), url::Url::parse(got)) else {
        return false;
    };
    want.scheme() == got.scheme()
        && want.username() == got.username()
        && want.password() == got.password()
        && want.host_str() == got.host_str()
        && want.port_or_known_default() == got.port_or_known_default()
        && want.fragment() == got.fragment()
        && segments(&want) == segments(&got)
        && same_form(
            want.query().unwrap_or_default().as_bytes(),
            got.query().unwrap_or_default().as_bytes(),
        )
}

/// The path of *url*, split at its `/` and each segment percent-decoded.
fn segments(url: &url::Url) -> Vec<Vec<u8>> {
    url.path()
        .split('/')
        .map(|segment| percent_encoding::percent_decode_str(segment).collect())
        .collect()
}

/// Whether two [`FORM`] texts (a form body, a query string) hold the same
/// fields once decoded: `+` and `%20`, `~` and `%7E`, `%2f` and `%2F` are
/// the same. Names may come in any order; the values of a repeated name must
/// come in the same order. A value is compared as text: `True` is not
/// `true`.
pub fn same_form(want: &[u8], got: &[u8]) -> bool {
    want == got || fields(want) == fields(got)
}

/// The decoded fields of a form text, ordered by name (a stable sort: a
/// repeated name's values stay in the order they came).
fn fields(text: &[u8]) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> =
        url::form_urlencoded::parse(text).into_owned().collect();
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    fields
}

/// Whether a request body sent says what the recorded one does: the same
/// bytes, or, when both are JSON, the same data. JSON is compared as values:
/// object keys in any order, any spacing, any escape (`\u00e9` or `é`); a
/// string that itself holds a JSON object or array (a rule passed as text)
/// is compared the same way. A body that is not JSON matches only byte for
/// byte.
pub fn same_body(want: &[u8], got: &[u8]) -> bool {
    if want == got {
        return true;
    }
    match (json(want), json(got)) {
        (Some(want), Some(got)) => same_value(&want, &got),
        _ => false,
    }
}

/// *bytes* as JSON, when they are.
fn json(bytes: &[u8]) -> Option<serde_json::Value> {
    serde_json::from_slice(bytes).ok()
}

/// A JSON object or array held as text in a string.
fn embedded(text: &str) -> Option<serde_json::Value> {
    let trimmed = text.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return None;
    }
    serde_json::from_str(text).ok()
}

/// Whether two JSON values hold the same data.
fn same_value(want: &serde_json::Value, got: &serde_json::Value) -> bool {
    use serde_json::Value;
    match (want, got) {
        (Value::Object(want), Value::Object(got)) => {
            want.len() == got.len()
                && want
                    .iter()
                    .all(|(key, value)| got.get(key).is_some_and(|other| same_value(value, other)))
        }
        (Value::Array(want), Value::Array(got)) => {
            want.len() == got.len()
                && want
                    .iter()
                    .zip(got)
                    .all(|(value, other)| same_value(value, other))
        }
        (Value::String(want), Value::String(got)) => {
            want == got
                || matches!(
                    (embedded(want), embedded(got)),
                    (Some(want), Some(got)) if same_value(&want, &got)
                )
        }
        _ => want == got,
    }
}
