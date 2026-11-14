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

/// One answer.
#[derive(Clone, Debug)]
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

impl Answer {
    /// Sends *request* on *http* and reads its answer whole.
    pub async fn fetch(
        http: &HttpClient,
        request: reqwest::Request,
        cancel: &CancellationToken,
    ) -> Result<Self, ConnectorError> {
        let started = Instant::now();
        let response = http.send(request, cancel).await?;
        let elapsed = started.elapsed();
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = http.bytes(response, cancel).await?;
        Ok(Self {
            status,
            content_type,
            body,
            elapsed,
        })
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
    request: reqwest::RequestBuilder,
) -> Result<Answer, ConnectorError> {
    let request = request.build().map_err(|error| ConnectorError::Setup {
        platform: cx.tenant.label.platform.clone(),
        tenant: cx.tenant.label.tenant.clone(),
        message: crate::error::describe(error),
    })?;
    Answer::fetch(cx.http, request, cx.cancel).await
}

/// Why an answer that is not the tenant's API is a gateway's, or `None`
/// (`gateway_answer`).
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
        .filter(|elapsed| *elapsed >= SLOW_ANSWER)
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
}
