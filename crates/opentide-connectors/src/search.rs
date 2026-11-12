//! What the query runners and the live checks of the platforms share
//! (`opentide.query.models`, `opentide.query.runner`): the request, the rows a
//! tenant returned, why a tenant refused a query, and the text helpers the
//! runners apply to a query before they send it.
//!
//! A row keeps its keys in the order the platform sent them (the Python
//! runners build dicts), so rows are `opentide_compile::json::Json`, whose
//! objects keep their insertion order.

use std::time::Duration;

use opentide_compile::json::{Json, Object};

use crate::error::ConnectorError;

/// `DEFAULT_LIMIT`: rows a query returns when the caller names no limit.
pub const DEFAULT_LIMIT: usize = 100;

/// `DEFAULT_TIMEOUT`: seconds a query may take when the caller names none.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// A query's time window (`TimeWindow`), both ends included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeWindow {
    /// The start.
    pub start: jiff::Timestamp,
    /// The end.
    pub end: jiff::Timestamp,
}

impl TimeWindow {
    /// The window's length in whole seconds, at least one (`seconds`).
    pub fn seconds(&self) -> i64 {
        let span = self.end.as_second() - self.start.as_second();
        let nanos = self.end.subsec_nanosecond() - self.start.subsec_nanosecond();
        // `int(total_seconds())` truncates toward zero.
        let whole = if nanos < 0 && span > 0 {
            span - 1
        } else if nanos > 0 && span < 0 {
            span + 1
        } else {
            span
        };
        whole.max(1)
    }

    /// The minute before *now* (`check_window`): `validate query --live`'s.
    pub fn check(now: jiff::Timestamp) -> Self {
        let start = now
            .checked_sub(jiff::SignedDuration::from_secs(60))
            .unwrap_or(now);
        Self { start, end: now }
    }
}

/// One query for one tenant (`QueryRequest`).
#[derive(Clone, Debug, PartialEq)]
pub struct SearchRequest {
    /// The query text.
    pub text: String,
    /// The window it searches.
    pub window: TimeWindow,
    /// Rows to return; one more is asked for, to tell a truncated result.
    pub limit: usize,
    /// The platform's language when it has several (Elastic); `None` takes
    /// the platform's first.
    pub language: Option<String>,
    /// Elastic's indices.
    pub index: Vec<String>,
    /// Elastic's data view.
    pub data_view: Option<String>,
    /// Seconds the query may take.
    pub timeout: Duration,
}

impl SearchRequest {
    /// A request for *text* over *window*, with the defaults.
    pub fn new(text: impl Into<String>, window: TimeWindow) -> Self {
        Self {
            text: text.into(),
            window,
            limit: DEFAULT_LIMIT,
            language: None,
            index: Vec::new(),
            data_view: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The same request for one row: a live check's (`QueryRunner.check`).
    #[must_use]
    pub fn for_check(&self) -> Self {
        Self {
            limit: 1,
            ..self.clone()
        }
    }
}

/// A column of the result (`QueryColumn`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    /// Its name.
    pub name: String,
    /// The vendor's type name, verbatim; `None` when it reports none.
    pub kind: Option<String>,
}

impl Column {
    /// A column without a type.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: None,
        }
    }
}

/// The rows one tenant returned for one query (`QueryResult`).
#[derive(Clone, Debug, PartialEq, Default)]
pub struct SearchResult {
    /// The columns.
    pub columns: Vec<Column>,
    /// The rows, each an object.
    pub rows: Vec<Json>,
    /// More rows matched than the limit let through.
    pub truncated: bool,
    /// The platform stopped early and says the rows are incomplete.
    pub partial: bool,
    /// The platform's reservations.
    pub warnings: Vec<String>,
    /// The platform's id of the search (SentinelOne's `queryId`, Kibana's
    /// preview id).
    pub vendor_query_id: Option<String>,
    /// What was sent, when the runner changed the query (a limit appended).
    pub sent: Option<String>,
    /// The language the query ran in.
    pub language: String,
}

/// Why a query got no rows.
#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    /// The platform answered and refused the query (`QueryRefused`).
    #[error("{message}")]
    Refused {
        /// What happened.
        message: String,
        /// The vendor's own message, when it gave one.
        detail: Option<String>,
    },
    /// The platform took the query and did not finish it in time
    /// (`QueryTimedOut`).
    #[error("{message}")]
    TimedOut {
        /// What happened.
        message: String,
        /// The deadline, in seconds.
        timeout: f64,
        /// What to do about it.
        detail: Option<String>,
    },
    /// The tenant refused the credentials (`TenantConnectionError`): every
    /// query of the tenant fails alike.
    #[error("{0}")]
    Tenant(String),
    /// The tenant could not be reached, or the run was cancelled.
    #[error(transparent)]
    Connector(#[from] ConnectorError),
}

impl SearchError {
    /// A refusal.
    pub fn refused(message: impl Into<String>, detail: Option<String>) -> Self {
        Self::Refused {
            message: message.into(),
            detail,
        }
    }

    /// The refusal and the vendor's own message as one line (`refusal_text`).
    pub fn text(&self) -> String {
        match self {
            Self::Refused {
                message,
                detail: Some(detail),
            }
            | Self::TimedOut {
                message,
                detail: Some(detail),
                ..
            } => format!("{message}: {detail}"),
            other => other.to_string(),
        }
    }
}

/// `format_utc_z`: UTC, milliseconds (truncated), `Z`.
pub fn utc_z(moment: jiff::Timestamp) -> String {
    let civil = jiff::tz::Offset::UTC.to_datetime(moment);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        civil.year(),
        civil.month(),
        civil.day(),
        civil.hour(),
        civil.minute(),
        civil.second(),
        civil.subsec_nanosecond() / 1_000_000
    )
}

/// `str(value)` of a JSON value as Python prints the parsed value: a string
/// as is, anything else in Python's `repr`.
pub fn python_str(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        other => python_repr(other),
    }
}

/// Python's `repr` of a parsed JSON value (`{'a': [1, None]}`), as an
/// error message that interpolates a body prints it.
pub fn python_repr(value: &Json) -> String {
    match value {
        Json::Null => "None".to_owned(),
        Json::Bool(true) => "True".to_owned(),
        Json::Bool(false) => "False".to_owned(),
        Json::Int(integer) => integer.to_string(),
        Json::Float(float) => opentide_schema::configuration::repr::float_text(*float),
        Json::Str(text) => python_string_repr(text),
        Json::Array(items) => {
            let inner: Vec<String> = items.iter().map(python_repr).collect();
            format!("[{}]", inner.join(", "))
        }
        Json::Object(object) => {
            let inner: Vec<String> = object
                .iter()
                .map(|(key, value)| format!("{}: {}", python_string_repr(key), python_repr(value)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// Python's `repr` of a string: single quotes unless the text holds one and
/// no double quote.
pub fn python_string_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python's truthiness of an optional value.
pub fn truthy(value: Option<&Json>) -> bool {
    value.is_some_and(Json::truthy)
}

/// `value.get(key)` when *value* is an object.
pub fn get<'j>(value: &'j Json, key: &str) -> Option<&'j Json> {
    value.get(key)
}

/// Nested objects as dotted keys (`flatten`); lists, scalars and empty
/// objects stay values.
pub fn flatten(document: &Object) -> Object {
    let mut flat = Object::new();
    flatten_into(document, "", &mut flat);
    flat
}

fn flatten_into(document: &Object, prefix: &str, flat: &mut Object) {
    for (key, value) in document {
        let name = format!("{prefix}{key}");
        match value {
            Json::Object(inner) if !inner.is_empty() => {
                flatten_into(inner, &format!("{name}."), flat);
            }
            other => {
                flat.insert(name, other.clone());
            }
        }
    }
}

/// The union of the rows' keys, in first-seen order (`columns_of`).
pub fn columns_of(rows: &[Json]) -> Vec<Column> {
    let mut names: Vec<String> = Vec::new();
    for row in rows {
        if let Json::Object(object) = row {
            for key in object.keys() {
                if !names.contains(key) {
                    names.push(key.clone());
                }
            }
        }
    }
    names.into_iter().map(Column::named).collect()
}

/// *query* with its `//` comments and string literals blanked, positions
/// (characters) kept (`kql_code`).
pub fn kql_code(query: &str) -> String {
    let chars: Vec<char> = query.chars().collect();
    let length = chars.len();
    let mut out = String::with_capacity(query.len());
    let mut index = 0;
    while index < length {
        let character = chars[index];
        if character == '/' && chars.get(index + 1) == Some(&'/') {
            let end = chars[index..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(length, |offset| index + offset);
            out.extend(std::iter::repeat_n(' ', end - index));
            index = end;
            continue;
        }
        if character == '\'' || character == '"' {
            let verbatim = index > 0 && chars[index - 1] == '@';
            let mut end = index + 1;
            while end < length && chars[end] != character {
                end += if chars[end] == '\\' && !verbatim {
                    2
                } else {
                    1
                };
            }
            let end = (end + 1).min(length);
            out.extend(std::iter::repeat_n(' ', end - index));
            index = end;
            continue;
        }
        out.push(character);
        index += 1;
    }
    out
}

/// Whether *text* ends in `| take N` or `| limit N` (`_KQL_TAIL`), any case.
fn ends_in_take(text: &str) -> bool {
    static TAIL: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    TAIL.get_or_init(|| regex::Regex::new(r"(?i)\|\s*(?:take|limit)\s+\d+\s*$").ok())
        .as_ref()
        .is_some_and(|tail| tail.is_match(text))
}

/// *query* with `| take limit+1` on a line of its own, unless it already
/// ends in `take` or `limit` (`kql_with_limit`).
pub fn kql_with_limit(query: &str, limit: usize) -> String {
    let text = query.trim_end().trim_end_matches(';').trim_end();
    if ends_in_take(kql_code(text).trim_end()) {
        return text.to_owned();
    }
    format!("{text}\n| take {}", limit.saturating_add(1))
}

/// Python's `str.strip()`: whitespace at both ends (Unicode's, as Python's).
pub fn strip(text: &str) -> &str {
    text.trim()
}

/// HTTP statuses a gateway answers when the tenant behind it does not.
const GATEWAY_STATUSES: [(u16, &str); 3] = [
    (502, "Bad Gateway"),
    (503, "Service Unavailable"),
    (504, "Gateway Timeout"),
];

/// Seconds after which an answer that is not the tenant's own is taken for a
/// gateway's.
const SLOW_ANSWER_SECONDS: f64 = 30.0;

/// An answer as the runners read it: status, `Content-Type`, body and how
/// long it took.
#[derive(Clone, Debug, PartialEq)]
pub struct Answer {
    /// The HTTP status.
    pub status: u16,
    /// The `Content-Type`, when there was one.
    pub content_type: Option<String>,
    /// The body.
    pub body: Vec<u8>,
    /// Seconds the request took.
    pub elapsed: f64,
}

impl Answer {
    /// The body as JSON (`response.json()`); `None` when it is not JSON.
    pub fn json(&self) -> Option<Json> {
        // `requests` decodes the body with its detected encoding; every API
        // here answers UTF-8. Python's `json.loads` refuses an empty body.
        serde_json::from_slice::<Json>(&self.body).ok()
    }

    /// The body as text (`response.text`), invalid UTF-8 replaced.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// `not_json_detail`: one line on an answer that is not JSON, else `None`.
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

/// `describe_answer`: an answer that is not the API's JSON, as one line.
pub fn describe_answer(
    status: u16,
    body: &[u8],
    content_type: Option<&str>,
    elapsed: Option<f64>,
) -> String {
    let kind = content_type
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let trimmed = body.trim_ascii_start();
    let head: Vec<u8> = trimmed
        .iter()
        .take(15)
        .map(u8::to_ascii_lowercase)
        .collect();
    let text =
        if kind == "text/html" || head.starts_with(b"<!doctype html") || head.starts_with(b"<html")
        {
            match page_title(body) {
                Some(title) => format!(
                    "HTTP {status} with an HTML page titled {}",
                    python_string_repr(&title)
                ),
                None => format!("HTTP {status} with an HTML page"),
            }
        } else if body.trim_ascii().is_empty() {
            format!("HTTP {status} with an empty body")
        } else {
            let head = &body[..body.len().min(200)];
            let snippet = String::from_utf8_lossy(head)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "HTTP {status} with a body that is not JSON ({})",
                python_string_repr(&snippet)
            )
        };
    match gateway_answer(status, elapsed) {
        Some(hint) => format!("{text}: {hint}"),
        None => text,
    }
}

/// `gateway_answer`: why an answer is a gateway's, or `None`.
pub fn gateway_answer(status: u16, elapsed: Option<f64>) -> Option<String> {
    if let Some((_, name)) = GATEWAY_STATUSES.iter().find(|(code, _)| *code == status) {
        return Some(format!(
            "HTTP {status} {name} is what a gateway or proxy in front of the tenant answers \
             when the tenant does not answer it in time, so the url and port are not at fault \
             when other requests to the same address succeed"
        ));
    }
    match elapsed {
        Some(seconds) if seconds >= SLOW_ANSWER_SECONDS => Some(format!(
            "it came after {seconds:.0}s, as from a gateway or proxy in front of the tenant \
             that stopped waiting for it"
        )),
        _ => None,
    }
}

/// The `<title>` of an HTML page, its whitespace collapsed (`page_title`).
pub fn page_title(body: &[u8]) -> Option<String> {
    let lowered: Vec<u8> = body.iter().map(u8::to_ascii_lowercase).collect();
    let open = find(&lowered, b"<title")?;
    let start = open + find(&lowered[open..], b">")? + 1;
    let end = start + find(&lowered[start..], b"</title>")?;
    let title = String::from_utf8_lossy(&body[start..end])
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (!title.is_empty()).then_some(title)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// `urllib.parse.quote(text, safe)`: every byte but ASCII letters, digits,
/// `_.-~` and *safe* as `%XX`.
pub fn quote(text: &str, safe: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric()
            || b"_.-~".contains(&byte)
            || (byte.is_ascii() && safe.as_bytes().contains(&byte))
        {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `urllib.parse.quote_plus(text)`: [`quote`] with no safe character and a
/// space as `+`.
pub fn quote_plus(text: &str) -> String {
    quote(text, " ").replace(' ', "+")
}

/// `urlencode(pairs)` as `requests` writes `params=` and `data=`.
pub fn urlencode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", quote_plus(key), quote_plus(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Sends *request* on the tenant's client and reads the whole answer.
pub async fn exchange(
    cx: crate::connector::TenantContext<'_>,
    request: reqwest::RequestBuilder,
) -> Result<Answer, ConnectorError> {
    let request = request.build().map_err(|error| ConnectorError::Setup {
        platform: cx.tenant.label.platform.clone(),
        tenant: cx.tenant.label.tenant.clone(),
        message: crate::error::describe(error),
    })?;
    let started = std::time::Instant::now();
    let response = cx.http.send(request, cx.cancel).await?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = cx.http.bytes(response, cx.cancel).await?;
    Ok(Answer {
        status,
        content_type,
        body,
        elapsed: started.elapsed().as_secs_f64(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_read_as_the_python_runners_do() {
        assert_eq!(kql_with_limit("T | take 5;", 100), "T | take 5");
        assert_eq!(
            kql_with_limit("T // | take 5", 100),
            "T // | take 5\n| take 101"
        );
        assert_eq!(
            kql_with_limit("T | where a == '| take 3'", 1),
            "T | where a == '| take 3'\n| take 2"
        );
        assert_eq!(
            quote_plus("alert.attributes.tags:\"OpenTide\" ~*"),
            "alert.attributes.tags%3A%22OpenTide%22+~%2A"
        );
        assert_eq!(quote("logs-*,x y", ",*-_."), "logs-*,x%20y");
        assert_eq!(
            python_repr(
                &serde_json::from_str::<Json>(r#"{"a": [1, null, true], "b": "it's"}"#)
                    .unwrap_or(Json::Null)
            ),
            r#"{'a': [1, None, True], 'b': "it's"}"#
        );
        assert_eq!(
            describe_answer(
                502,
                b"<html><title> Bad\n Gateway </title></html>",
                Some("text/html"),
                None
            ),
            "HTTP 502 with an HTML page titled 'Bad Gateway': HTTP 502 Bad Gateway is what a gateway or proxy in front of the tenant answers when the tenant does not answer it in time, so the url and port are not at fault when other requests to the same address succeed"
        );
        assert_eq!(
            describe_answer(404, b"", None, Some(0.1)),
            "HTTP 404 with an empty body"
        );
        let start: jiff::Timestamp = "2026-10-26T08:00:00.9999Z".parse().unwrap_or_default();
        assert_eq!(utc_z(start), "2026-10-26T08:00:00.999Z");
        let end: jiff::Timestamp = "2026-10-26T08:00:02.5Z".parse().unwrap_or_default();
        assert_eq!(TimeWindow { start, end }.seconds(), 1);
    }
}
