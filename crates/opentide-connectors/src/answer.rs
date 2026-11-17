//! A tenant's answer, read whole: its status, its type, its bytes and how
//! long it took, and what to say about one that is not the API's JSON
//! (`platforms/transport.py` `describe_answer`, `not_json_detail`).

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use opentide_compile::Json;
use tokio_util::sync::CancellationToken;

use crate::connector::TenantContext;
use crate::error::ConnectorError;
use crate::http::HttpClient;

/// An answer slower than this that is not the API's is read as a gateway's
/// (`SLOW_ANSWER_SECONDS`).
pub const SLOW_ANSWER: Duration = Duration::from_secs(30);

/// One answer. Its `Debug` leaves the body out: a token endpoint's answer
/// carries a bearer token. Its body is kept as it came, for [`json`](Self::json)
/// to read the API's data; every quote of it ([`text`](Self::text),
/// [`text_head`](Self::text_head), [`not_json_detail`](Self::not_json_detail))
/// has the request's [`Credentials`] masked.
#[derive(Clone)]
pub struct Answer {
    /// The HTTP status.
    pub status: u16,
    /// The `Content-Type` header.
    pub content_type: Option<String>,
    /// The body.
    pub body: Vec<u8>,
    /// From sending the request to its headers (`requests`' `elapsed`).
    pub elapsed: Duration,
    /// What the request sent as a credential, masked in every quote.
    pub credentials: Credentials,
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Answer")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("body_bytes", &self.body.len())
            .field("elapsed", &self.elapsed)
            .field("credentials", &self.credentials)
            .finish()
    }
}

/// What the request itself carries as a credential, to keep out of what the
/// API says back: an answer may echo the `Authorization` header it got.
#[derive(Clone, Default)]
pub struct Credentials(Vec<String>);

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credentials({} masked)", self.0.len())
    }
}

/// A credential shorter than this is not masked: a short word (a Basic
/// password like `token`) would be hidden wherever the answer says it.
const MIN_CREDENTIAL: usize = 8;

/// The fields of a form or JSON body that hold a credential (a token
/// endpoint's).
const FORM_CREDENTIALS: [&str; 6] = [
    "client_secret",
    "client_assertion",
    "assertion",
    "refresh_token",
    "password",
    "api_key",
];

impl Credentials {
    /// The credentials *request* sends: the value of each `Authorization`,
    /// `Proxy-Authorization`, `X-API-Key` and `X-Auth-Token` header (and any
    /// header marked sensitive): its parameter after the scheme, or the value
    /// whole with none, and a Basic header's decoded user and password; and
    /// the credential fields of a form body or a JSON object body.
    pub fn of(request: &crate::transport::Request) -> Self {
        use crate::transport::header;
        use base64::Engine as _;
        let named = [
            header::AUTHORIZATION,
            header::PROXY_AUTHORIZATION,
            header::HeaderName::from_static("x-api-key"),
            header::HeaderName::from_static("x-auth-token"),
        ];
        let mut found = Vec::new();
        for (name, value) in request.headers() {
            if !value.is_sensitive() && !named.contains(name) {
                continue;
            }
            let Ok(value) = value.to_str() else { continue };
            // `Bearer <token>`: the token, the scheme staying readable; a
            // value with no scheme (an API key) is the credential whole.
            let Some((scheme, parameter)) = value.trim().split_once(' ') else {
                found.push(value.trim().to_owned());
                continue;
            };
            let parameter = parameter.trim();
            found.push(parameter.to_owned());
            if scheme.eq_ignore_ascii_case("basic") {
                let decoded = base64::engine::general_purpose::STANDARD.decode(parameter);
                if let Some(pair) = decoded.ok().and_then(|bytes| String::from_utf8(bytes).ok()) {
                    // A password may hold a colon: split once.
                    found.extend(pair.splitn(2, ':').map(str::to_owned));
                }
            }
        }
        // A form body names its credentials: `client_secret=...` is one.
        let is_form = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|kind| kind.contains("application/x-www-form-urlencoded"));
        match (is_form, request.body()) {
            (true, Some(body)) => found.extend(
                url::form_urlencoded::parse(body)
                    .filter(|(name, _)| FORM_CREDENTIALS.contains(&name.as_ref()))
                    .map(|(_, value)| value.into_owned()),
            ),
            // `{"client_id": ..., "client_secret": ...}`, as Exabeam signs in.
            (false, Some(body)) => {
                if let Ok(serde_json::Value::Object(fields)) = serde_json::from_slice(body) {
                    found.extend(
                        fields
                            .iter()
                            .filter(|(name, _)| FORM_CREDENTIALS.contains(&name.as_str()))
                            .filter_map(|(_, value)| value.as_str().map(str::to_owned)),
                    );
                }
            }
            _ => {}
        }
        found.retain(|credential| credential.len() >= MIN_CREDENTIAL);
        // The longest first, so a credential that holds another is masked
        // whole, not left with a tail.
        found.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        found.dedup();
        Self(found)
    }

    /// *body* with each credential it echoes replaced by `***`; the bytes
    /// themselves when it echoes none.
    pub fn mask(&self, body: Vec<u8>) -> Vec<u8> {
        let text = String::from_utf8_lossy(&body);
        if !self.echoed(&text) {
            return body;
        }
        self.mask_text(&text).into_bytes()
    }

    /// *text* with each credential it holds replaced by `***`.
    pub fn mask_text(&self, text: &str) -> String {
        if !self.echoed(text) {
            return text.to_owned();
        }
        self.0.iter().fold(text.to_owned(), |text, credential| {
            text.replace(credential.as_str(), "***")
        })
    }

    /// Every string and key of *json* with each credential it holds
    /// replaced by `***`. Keys that mask to the same text are kept apart:
    /// the second is `***#2`, the third `***#3`, so no member is lost.
    fn mask_json(&self, json: &mut Json) {
        match json {
            Json::Str(text) => {
                if self.echoed(text) {
                    *text = self.mask_text(text);
                }
            }
            Json::Array(items) => items.iter_mut().for_each(|item| self.mask_json(item)),
            Json::Object(object) => {
                let members = std::mem::take(object);
                for (key, mut value) in members {
                    self.mask_json(&mut value);
                    let masked = self.mask_text(&key);
                    let mut name = masked.clone();
                    let mut copy = 1;
                    while object.contains_key(name.as_str()) {
                        copy += 1;
                        name = format!("{masked}#{copy}");
                    }
                    object.insert(name, value);
                }
            }
            Json::Null | Json::Bool(_) | Json::Int(_) | Json::UInt(_) | Json::Float(_) => {}
        }
    }

    fn echoed(&self, text: &str) -> bool {
        self.0
            .iter()
            .any(|credential| text.contains(credential.as_str()))
    }
}

impl Answer {
    /// An answer to a request that sent *credentials*: its body is kept as
    /// it came, and every quote of it masks them, whatever its status or
    /// shape, before any cut, so no cut can show the head of one that
    /// straddles it.
    pub fn new(
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
        elapsed: Duration,
        credentials: &Credentials,
    ) -> Self {
        Self {
            status,
            content_type,
            body,
            elapsed,
            credentials: credentials.clone(),
        }
    }

    /// Sends *request* on *http* and reads its answer whole.
    pub async fn fetch(
        http: &HttpClient,
        request: crate::transport::Request,
        cancel: &CancellationToken,
    ) -> Result<Self, ConnectorError> {
        let credentials = Credentials::of(&request);
        let started = Instant::now();
        let response = http.send(request, cancel).await?;
        // To the answer's headers, retries included: the transport reads
        // the body before `send` returns, so its reading is taken off.
        let elapsed = started.elapsed().saturating_sub(response.reading());
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = http.bytes(response, cancel).await?;
        Ok(Self::new(status, content_type, body, elapsed, &credentials))
    }

    /// The body as JSON, keys in order; `None` when it is not JSON
    /// (`response.json()` raising). The data a client reads (a token
    /// endpoint's `access_token`, which may hold the request's credential):
    /// it is read as it came. Whatever an error quotes comes from
    /// [`Answer::quotable_json`] instead.
    pub fn json(&self) -> Option<Json> {
        serde_json::from_slice(&self.body).ok()
    }

    /// The body as JSON for a field an error or a message copies out of it:
    /// each string and key that holds one of the request's credentials has
    /// it replaced by `***`, as [`Answer::text`] masks the text.
    pub fn quotable_json(&self) -> Option<Json> {
        let mut json = self.json()?;
        self.credentials.mask_json(&mut json);
        Some(json)
    }

    /// *part* of the body (read with [`Answer::json`]) as
    /// [`Answer::quotable_json`] would give it, for a field copied out of an
    /// answer whose other fields are the data the caller returns as it came.
    pub fn quoted(&self, part: &Json) -> Json {
        let mut part = part.clone();
        self.credentials.mask_json(&mut part);
        part
    }

    /// The body as text, invalid UTF-8 replaced (`response.text`), the
    /// request's credentials masked.
    pub fn text(&self) -> String {
        self.credentials
            .mask_text(&String::from_utf8_lossy(&self.body))
    }

    /// The first *chars* characters of the text (`response.text[:chars]`).
    pub fn text_head(&self, chars: usize) -> String {
        self.text().chars().take(chars).collect()
    }

    /// Why a page that should be JSON is not, naming its `Content-Type`
    /// (`the page is not JSON (Content-Type text/html): HTTP 200 with an HTML
    /// page titled "Sign in"`), else `None`: a listing reads such a page as
    /// an error, never as an empty page (#1142).
    pub fn not_json_page(&self) -> Option<String> {
        let detail = self.not_json_detail()?;
        let kind = self.content_type.as_deref().map_or_else(
            || "no Content-Type".to_owned(),
            |kind| format!("Content-Type {kind}"),
        );
        Some(format!("the page is not JSON ({kind}): {detail}"))
    }

    /// [`describe_answer`] for a body that is not JSON, else `None`
    /// (`not_json_detail`).
    pub fn not_json_detail(&self) -> Option<String> {
        if self.json().is_some() {
            return None;
        }
        Some(describe_answer(
            self.status,
            self.text().as_bytes(),
            self.content_type.as_deref(),
            Some(self.elapsed),
        ))
    }
}

/// Sends *request* on the tenant's client and reads the whole answer; a
/// request that cannot be built is the tenant's setup error.
pub async fn exchange(
    cx: TenantContext<'_>,
    request: crate::transport::RequestBuilder,
) -> Result<Answer, ConnectorError> {
    let request = request.build().map_err(|error| ConnectorError::Setup {
        platform: cx.tenant.label.platform.clone(),
        tenant: cx.tenant.label.tenant.clone(),
        message: error.describe(),
    })?;
    Answer::fetch(cx.http, request, cx.cancel).await
}

/// Why an answer that is not the tenant's API is a gateway's, or `None`
/// (`gateway_answer`). A `429` is the API's rate limit, however long it
/// took: its `elapsed` counts the `Retry-After` waits before it.
pub fn gateway_answer(status: u16, elapsed: Option<Duration>) -> Option<String> {
    let name = match status {
        502 => Some("Bad Gateway"),
        503 => Some("Service Unavailable"),
        504 => Some("Gateway Timeout"),
        _ => None,
    };
    if let Some(name) = name {
        return Some(format!(
            "HTTP {status} {name} is what a gateway or proxy in front of the tenant answers \
             when the tenant does not answer it in time, so the url and port are not at fault \
             when other requests to the same address succeed"
        ));
    }
    elapsed
        .filter(|elapsed| status != 429 && *elapsed >= SLOW_ANSWER)
        .map(|elapsed| {
            format!(
                "it came after {:.0}s, as from a gateway or proxy in front of the tenant that \
             stopped waiting for it",
                elapsed.as_secs_f64()
            )
        })
}

/// The `<title>` of an HTML page (`page_title`).
pub fn page_title(body: &[u8]) -> Option<String> {
    static TITLE: OnceLock<Option<regex::bytes::Regex>> = OnceLock::new();
    let title = TITLE
        .get_or_init(|| regex::bytes::Regex::new(r"(?is)<title[^>]*>(.*?)</title>").ok())
        .as_ref()?;
    let found = title.captures(body)?.get(1)?;
    let text = String::from_utf8_lossy(found.as_bytes());
    let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
    (!joined.is_empty()).then_some(joined)
}

/// One line on an answer that is not the API's JSON: its status, its body
/// and a gateway's reading (`describe_answer`). It quotes *body* as given:
/// a caller passes the masked text ([`Answer::not_json_detail`] does), never
/// the raw bytes of an answer to a request that sent a credential.
pub fn describe_answer(
    status: u16,
    body: &[u8],
    content_type: Option<&str>,
    elapsed: Option<Duration>,
) -> String {
    let kind = content_type
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let trimmed = body.trim_ascii_start();
    let head = trimmed[..trimmed.len().min(15)].to_ascii_lowercase();
    let text =
        if kind == "text/html" || head.starts_with(b"<!doctype html") || head.starts_with(b"<html")
        {
            match page_title(body) {
                Some(title) => format!("HTTP {status} with an HTML page titled {title:?}"),
                None => format!("HTTP {status} with an HTML page"),
            }
        } else if body.trim_ascii().is_empty() {
            format!("HTTP {status} with an empty body")
        } else {
            let snippet = String::from_utf8_lossy(&body[..body.len().min(200)]);
            let snippet = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
            format!("HTTP {status} with a body that is not JSON ({snippet:?})")
        };
    match gateway_answer(status, elapsed) {
        Some(hint) => format!("{text}: {hint}"),
        None => text,
    }
}

/// A `400` JSON answer *body* to a request that sent the bearer
/// [`TEST_BEARER`], for the tests of what an error quotes from an answer.
#[cfg(test)]
pub(crate) fn answer_to_bearer(body: &str) -> Answer {
    let mut request = crate::transport::Request::new(
        crate::transport::Method::GET,
        "https://example.test/".parse().unwrap(),
    );
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {TEST_BEARER}").parse().unwrap(),
    );
    Answer::new(
        400,
        Some("application/json".into()),
        body.as_bytes().to_vec(),
        Duration::ZERO,
        &Credentials::of(&request),
    )
}

/// The bearer [`answer_to_bearer`] sends.
#[cfg(test)]
pub(crate) const TEST_BEARER: &str = "abcdefgh12345678";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_leaves_the_body_out() {
        let answer = Answer {
            status: 200,
            content_type: Some("application/json".into()),
            body: br#"{"access_token":"eyJ.secret.token","expires_in":3599}"#.to_vec(),
            elapsed: Duration::from_millis(5),
            credentials: crate::answer::Credentials::default(),
        };
        let shown = format!("{answer:?}");
        assert!(!shown.contains("eyJ.secret.token"), "{shown}");
        assert!(
            shown.contains("status: 200") && shown.contains("body_bytes: 53"),
            "{shown}"
        );
    }

    fn request_with(name: &'static str, value: &str) -> crate::transport::Request {
        let mut request = crate::transport::Request::new(
            crate::transport::Method::GET,
            "https://example.test/".parse().unwrap(),
        );
        request.headers_mut().insert(name, value.parse().unwrap());
        request
    }

    #[test]
    fn a_credential_is_masked_whole_and_by_its_parameter() {
        let credentials =
            Credentials::of(&request_with("authorization", "Bearer abcdefgh12345678"));
        let body = b"Bearer abcdefgh12345678 and abcdefgh12345678".to_vec();
        let masked = String::from_utf8(credentials.mask(body)).unwrap();
        assert_eq!(masked, "Bearer *** and ***");
    }

    #[test]
    fn a_basic_header_masks_its_user_and_leaves_a_short_password() {
        // user "a-user-name", password "token".
        let credentials = Credentials::of(&request_with(
            "proxy-authorization",
            "Basic YS11c2VyLW5hbWU6dG9rZW4=",
        ));
        let masked = credentials.mask(b"a-user-name token".to_vec());
        assert_eq!(String::from_utf8(masked).unwrap(), "*** token");
    }

    #[test]
    fn a_basic_password_with_a_colon_is_masked_whole() {
        use base64::Engine as _;
        let pair = base64::engine::general_purpose::STANDARD.encode("a-user-name:pass:word-1234");
        let credentials = Credentials::of(&request_with("authorization", &format!("Basic {pair}")));
        let masked = credentials.mask(b"pass:word-1234 a-user-name".to_vec());
        assert_eq!(String::from_utf8(masked).unwrap(), "*** ***");
    }

    /// A field an error copies out of the JSON (a message, a list entry, a
    /// key) is masked as the text is, and an answer echoing nothing is read
    /// as it came.
    #[test]
    fn quotable_json_is_masked_like_the_text() {
        let credentials =
            Credentials::of(&request_with("authorization", "Bearer abcdefgh12345678"));
        let answer = |body: &str| {
            Answer::new(
                401,
                Some("application/json".into()),
                body.as_bytes().to_vec(),
                Duration::ZERO,
                &credentials,
            )
        };
        let echoed = answer(
            r#"{"error":{"message":"bad Bearer abcdefgh12345678","list":["abcdefgh12345678",7]},"abcdefgh12345678":true}"#,
        );
        assert_eq!(
            echoed.quotable_json().unwrap().to_compact(),
            r#"{"error":{"message":"bad Bearer ***","list":["***",7]},"***":true}"#
        );
        assert!(!echoed.text().contains("abcdefgh12345678"));
        // The data a client reads is as it came.
        assert!(
            echoed
                .json()
                .unwrap()
                .to_compact()
                .contains("abcdefgh12345678")
        );
        let plain = r#"{"b":[1,{"a":"x"}],"a":null}"#;
        assert_eq!(answer(plain).quotable_json().unwrap().to_compact(), plain);
    }

    /// A credential the API writes with JSON escapes is not in the raw
    /// bytes, but is in the string they decode to: it is masked there, and
    /// two keys that mask alike are both kept.
    #[test]
    fn quotable_json_masks_escaped_credentials_and_keeps_every_key() {
        let credentials =
            Credentials::of(&request_with("authorization", "Bearer abcd/efgh12345678"));
        let answer = |body: &str| {
            Answer::new(
                400,
                Some("application/json".into()),
                body.as_bytes().to_vec(),
                Duration::ZERO,
                &credentials,
            )
        };
        let escaped = answer(r#"{"message":"bad abcd\/efgh12345678 or \u0061bcd/efgh12345678"}"#);
        assert!(!escaped.body.windows(9).any(|w| w == b"abcd/efgh"));
        assert_eq!(
            escaped.quotable_json().unwrap().to_compact(),
            r#"{"message":"bad *** or ***"}"#
        );
        let keys = answer(r#"{"abcd/efgh12345678":1,"x":2,"***":3}"#);
        assert_eq!(
            keys.quotable_json().unwrap().to_compact(),
            r#"{"***":1,"x":2,"***#2":3}"#
        );
    }

    #[test]
    fn a_credential_holding_another_is_masked_whole() {
        let mut request = request_with("authorization", "Bearer abcdefgh12345678-and-more");
        request
            .headers_mut()
            .insert("x-api-key", "abcdefgh12345678".parse().unwrap());
        let masked = Credentials::of(&request).mask(b"abcdefgh12345678-and-more".to_vec());
        assert_eq!(String::from_utf8(masked).unwrap(), "***");
    }

    #[test]
    fn a_form_body_credential_is_masked() {
        let mut request = request_with("content-type", "application/x-www-form-urlencoded");
        request.set_body(Some(
            b"grant_type=refresh_token&client_secret=s3cr3t%2Bvalue%21&scope=x".to_vec(),
        ));
        let masked = Credentials::of(&request).mask(b"bad client s3cr3t+value! x".to_vec());
        assert_eq!(String::from_utf8(masked).unwrap(), "bad client *** x");
    }

    #[test]
    fn a_short_credential_is_not_masked() {
        let credentials = Credentials::of(&request_with("x-api-key", "short"));
        assert_eq!(credentials.mask(b"a short key".to_vec()), b"a short key");
    }

    #[test]
    fn a_gateway_page_is_named_by_its_title() {
        let page = b"<html><head><title>502  Bad\nGateway</title></head></html>";
        let line = describe_answer(502, page, Some("text/html; charset=utf-8"), None);
        assert!(line.starts_with(
            "HTTP 502 with an HTML page titled \"502 Bad Gateway\": HTTP 502 Bad Gateway is what"
        ));
        assert_eq!(
            describe_answer(200, b"  ", None, None),
            "HTTP 200 with an empty body"
        );
        assert_eq!(
            describe_answer(418, b"I'm a  teapot", None, None),
            "HTTP 418 with a body that is not JSON (\"I'm a teapot\")"
        );
        assert!(
            describe_answer(200, b"<!DOCTYPE html><p>x", None, Some(Duration::from_secs(31)))
                .ends_with("it came after 31s, as from a gateway or proxy in front of the tenant that stopped waiting for it")
        );
        assert_eq!(gateway_answer(500, Some(Duration::from_secs(29))), None);
    }

    #[test]
    fn a_429_after_its_retry_after_waits_is_no_gateway_answer() {
        // Two `Retry-After: 20` waits, then a third 429: 40 s, the API's.
        let waited = Some(Duration::from_secs(40));
        assert_eq!(gateway_answer(429, waited), None);
        assert_eq!(
            describe_answer(429, b"Too Many Requests", Some("text/plain"), waited),
            "HTTP 429 with a body that is not JSON (\"Too Many Requests\")"
        );
        // Any other slow answer still reads as a gateway's.
        assert!(gateway_answer(500, waited).is_some_and(|hint| hint.contains("after 40s")));
    }
}
