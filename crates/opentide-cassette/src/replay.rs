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
//!   On a request to an OAuth2 token endpoint, `Accept` is left out on both
//!   sides too: the endpoint answers JSON whatever it says (RFC 6749 §5.1).
//! - **Body**: a form body (the recorded request's `Content-Type` is
//!   `application/x-www-form-urlencoded`) as its decoded fields
//!   ([`same_form`]), as the query, but for [`IGNORED_FORM_FIELDS`] in a
//!   request to Entra ID's token endpoint; a JSON
//!   body as the same data
//!   ([`same_body`]): key order, spacing and escapes are layout; any other
//!   body byte for byte.
//! - **Order**: the requests in the order recorded, but for the requests
//!   a client may leave out ([`optional`]): a `POST` to an OAuth2 token
//!   endpoint that repeats an earlier recorded one (the same URL and
//!   body), where the recording client signed in again and the replayed one
//!   still holds a valid token (the first sign-in of every pass is never
//!   optional); and a `GET` of Entra ID's OpenID Provider configuration
//!   (`https://login.microsoftonline.com/…/.well-known/openid-configuration`),
//!   the discovery MSAL made before a client-credentials sign-in, which
//!   needs none.
//!
//! A cassette replays as many times as it is run through: after its last
//! interaction the next request is compared with its first. Each pass must
//! be whole: a test that runs a command twice must send the scenario's
//! requests each time (an optional one aside).

use std::sync::{Arc, Mutex, PoisonError};

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

/// Whether the client may leave out the request at *position* of the
/// cassette's cycle (interaction `position % len`): a `POST` to an OAuth2
/// token endpoint (a path ending in `/oauth2/token` or
/// `/oauth2/v2.0/token`) whose URL and body an earlier interaction of the
/// same pass already holds. A client that keeps its token until it nearly
/// expires does not sign in again where the recording client did; the
/// first sign-in of each pass is never optional.
pub fn optional(interactions: &[Interaction], position: usize) -> bool {
    let len = interactions.len();
    if len == 0 {
        return false;
    }
    let request = &interactions[position % len].request;
    if request.method == "GET" && is_entra_discovery(&request.url) {
        return true;
    }
    if request.method != "POST" || !is_token_endpoint(&request.url) {
        return false;
    }
    // Within its own pass only: each pass signs in at least once, as each
    // run of a command starts with no token.
    interactions[..position % len].iter().any(|earlier| {
        earlier.request.method == request.method
            && earlier.request.url == request.url
            && earlier.request.body == request.body
    })
}

/// The path of *url*, empty when it is not a URL.
fn path_of(url: &str) -> String {
    url::Url::parse(url)
        .map(|url| url.path().to_owned())
        .unwrap_or_default()
}

/// Whether *url* is an OAuth2 token endpoint: its path ends in
/// `/oauth2/token` or `/oauth2/v2.0/token`.
fn is_token_endpoint(url: &str) -> bool {
    let path = path_of(url);
    path.ends_with("/oauth2/token") || path.ends_with("/oauth2/v2.0/token")
}

/// Entra ID's sign-in host, the only one whose OpenID discovery and MSAL
/// form fields the matcher passes over.
const ENTRA_HOST: &str = "login.microsoftonline.com";

/// Whether *url* is on [`ENTRA_HOST`] over HTTPS.
fn on_entra(url: &str) -> bool {
    url::Url::parse(url)
        .is_ok_and(|url| url.scheme() == "https" && url.host_str() == Some(ENTRA_HOST))
}

/// Whether *url* is Entra ID's OpenID Provider configuration
/// (`https://login.microsoftonline.com/…/.well-known/openid-configuration`).
fn is_entra_discovery(url: &str) -> bool {
    on_entra(url) && path_of(url).ends_with("/.well-known/openid-configuration")
}

/// Serves each request the answer of the next interaction it matches,
/// passing over the optional ones it does not.
struct Sequence {
    interactions: Vec<Interaction>,
    next: Arc<Mutex<usize>>,
    redaction: Redaction,
    origin: Option<String>,
}

impl Respond for Sequence {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let got = received(request, self.origin.as_deref(), &self.redaction);
        let len = self.interactions.len();
        let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
        let mut position = *next;
        while len > 0 && position < *next + len {
            let interaction = &self.interactions[position % len];
            if differences(&interaction.request, &got).is_none() {
                *next = position + 1;
                let answer = &interaction.response;
                let mut template = ResponseTemplate::new(answer.status);
                for (name, value) in &answer.headers {
                    template = template.append_header(name.as_str(), value.as_str());
                }
                return template.set_body_bytes(answer.body.bytes());
            }
            if !optional(&self.interactions, position) {
                break;
            }
            position += 1;
        }
        ResponseTemplate::new(MISMATCH_STATUS)
            .set_body_string("not the request the cassette expects here")
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
        Mock::given(wiremock::matchers::any())
            .respond_with(Sequence {
                interactions: cassette.interactions.clone(),
                next: Arc::new(Mutex::new(0)),
                redaction: redaction.clone(),
                origin: origin.clone(),
            })
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
    /// played as many whole times as the requests need (at least once),
    /// the optional requests ([`optional`]) left out where the client did.
    pub async fn verify(&self) -> Vec<Mismatch> {
        verify(&self.cassette.interactions, &self.requests().await)
    }
}

/// Every difference between *actual* and *interactions* played as many
/// whole times as *actual* needs (at least once): each request is compared
/// with the next recorded one, passing over optional ones it does not
/// match ([`optional`]); a recorded request never sent is a difference
/// unless it is optional.
pub fn verify(interactions: &[Interaction], actual: &[cassette::Request]) -> Vec<Mismatch> {
    let len = interactions.len();
    let mut mismatches = Vec::new();
    let mut position = 0;
    for (index, got) in actual.iter().enumerate() {
        if len == 0 {
            mismatches.push(Mismatch {
                index,
                detail: format!(
                    "{} {} was sent and is not in the cassette",
                    got.method, got.url
                ),
            });
            continue;
        }
        let mut at = position;
        // The first recorded request that is not optional, or matches.
        let detail = loop {
            let detail = differences(&interactions[at % len].request, got);
            if detail.is_none() || !optional(interactions, at) || at + 1 >= position + len {
                break detail;
            }
            at += 1;
        };
        if let Some(detail) = detail {
            mismatches.push(Mismatch { index, detail });
        }
        position = at + 1;
    }
    let end = if len == 0 {
        0
    } else {
        position.div_ceil(len).max(1) * len
    };
    let sent = actual.len();
    for at in position..end {
        if !optional(interactions, at) {
            let want = &interactions[at % len].request;
            mismatches.push(Mismatch {
                index: sent + (at - position),
                detail: format!("{} {} was recorded and never sent", want.method, want.url),
            });
        }
    }
    mismatches
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
    let (mut want_headers, mut got_headers) = (meaningful(&want.headers), meaningful(&got.headers));
    if is_token_endpoint(&want.url) {
        want_headers.retain(|(name, _)| name != "accept");
        got_headers.retain(|(name, _)| name != "accept");
    }
    if want_headers != got_headers {
        return Some(format!(
            "headers {want_headers:?} were recorded, {got_headers:?} sent"
        ));
    }
    let (want_body, got_body) = (want.body.bytes(), got.body.bytes());
    let same = if is_form(&want.headers) && on_entra(&want.url) && is_token_endpoint(&want.url) {
        want_body == got_body || form_fields(&want_body) == form_fields(&got_body)
    } else if is_form(&want.headers) {
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

/// Whether two `application/x-www-form-urlencoded` texts (a form body, a query string) hold the same
/// fields once decoded: `+` and `%20`, `~` and `%7E`, `%2f` and `%2F` are
/// the same. Names may come in any order; the values of a repeated name must
/// come in the same order. A value is compared as text: `True` is not
/// `true`.
pub fn same_form(want: &[u8], got: &[u8]) -> bool {
    want == got || fields(want) == fields(got)
}

/// Form body fields that only a client library sends and the server ignores,
/// left out on both sides of a `POST` to Entra ID's token endpoint (and
/// nowhere else): `client_info`, which MSAL adds to ask for account
/// information that Entra ID does not return for the client-credentials
/// grant.
pub const IGNORED_FORM_FIELDS: [&str; 1] = ["client_info"];

/// A form body's decoded fields ([`fields`]) without
/// [`IGNORED_FORM_FIELDS`].
fn form_fields(text: &[u8]) -> Vec<(String, String)> {
    let mut fields = fields(text);
    fields.retain(|(name, _)| !IGNORED_FORM_FIELDS.contains(&name.as_str()));
    fields
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
