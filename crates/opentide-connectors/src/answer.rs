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
/// carries a bearer token.
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
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Answer")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("body_bytes", &self.body.len())
            .field("elapsed", &self.elapsed)
            .finish()
    }
}

/// What the request itself carries as a credential, to keep out of what the
/// API says back: an answer may echo the `Authorization` header it got.
#[derive(Clone, Debug, Default)]
pub struct Credentials(Vec<String>);

/// A credential shorter than this is not masked: a short word (a Basic
/// password like `token`) would be hidden wherever the answer says it.
const MIN_CREDENTIAL: usize = 8;

/// The fields of a form body that hold a credential (a token endpoint's).
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
    /// whole with none, and a Basic header's decoded user and password.
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
        if let (true, Some(body)) = (is_form, request.body()) {
            found.extend(
                url::form_urlencoded::parse(body)
                    .filter(|(name, _)| FORM_CREDENTIALS.contains(&name.as_ref()))
                    .map(|(_, value)| value.into_owned()),
            );
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
        if !self
            .0
            .iter()
            .any(|credential| text.contains(credential.as_str()))
        {
            return body;
        }
        self.0
            .iter()
            .fold(text.into_owned(), |text, credential| {
                text.replace(credential.as_str(), "***")
            })
            .into_bytes()
    }
}

impl Answer {
    /// An answer to a request that sent *credentials*. A successful JSON
    /// answer is the API's data and is kept as it came (a token endpoint's
    /// token may well contain the secret it was asked with); any other
    /// answer, an error status or a body that is not JSON, is only ever
    /// quoted, so it has none of the credentials: no cut of it, whatever its
    /// length, can show one the API echoed, nor the head of one that
    /// straddles the cut.
    pub fn new(
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
        elapsed: Duration,
        credentials: &Credentials,
    ) -> Self {
        let data = status < 400 && serde_json::from_slice::<serde::de::IgnoredAny>(&body).is_ok();
        Self {
            status,
            content_type,
            body: if data { body } else { credentials.mask(body) },
            elapsed,
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
    /// (`response.json()` raising).
    pub fn json(&self) -> Option<Json> {
        serde_json::from_slice(&self.body).ok()
    }

    /// The body as text, invalid UTF-8 replaced (`response.text`).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The first *chars* characters of the text (`response.text[:chars]`).
    pub fn text_head(&self, chars: usize) -> String {
        self.text().chars().take(chars).collect()
    }

    /// [`describe_answer`] for a body that is not JSON, else `None`
    /// (`not_json_detail`).
    pub fn not_json_detail(&self) -> Option<String> {
        if self.json().is_some() {
            return None;
        }
        Some(describe_answer(
            self.status,
            &self.body,
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
/// and a gateway's reading (`describe_answer`).
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
