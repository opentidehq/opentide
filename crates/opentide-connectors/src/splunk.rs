//! Splunk's management API (UC-4.3, #833): what `platforms/splunk/client.py`
//! sends through the Python Splunk client on opentide's urllib handler, request for request:
//! the saved searches its `deployer.py` writes (`_apply_saved_search`),
//! `runner.py`'s one-shot searches (`opentide query`) and its `search/parser`
//! check (`validate query --live`), and the `server/info` reads the Python Splunk client
//! makes to choose between the v1 and v2 search endpoints.
//!
//! Every call carries `Authorization: Splunk <token>` (the token as is when
//! it already starts with `Splunk `); a body is a form (`urlencode`), with
//! `Content-Type: application/x-www-form-urlencoded`. The tenant is
//! `https://<url>:<port>`, and every path but `server/info` is under the
//! app's namespace (`/servicesNS/nobody/<app>/`). An HTML page in place of
//! the API's answer is a gateway's or a proxy's (`_html_answer`).

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Duration;

use opentide_compile::json::{Json, Object};

use crate::answer::{Answer, describe_answer, gateway_answer, page_title};
use crate::connector::{
    BoxFuture, DeployOutcome, DeployRequest, Deployer, LiveCheck, LiveValidator, Operation,
    Platform, QueryColumn, QueryOutcome, QueryRequest, QueryRunner, Row, TenantContext, columns_of,
};
use crate::encode::{quote, quote_plus, urlencode};
use crate::error::ConnectorError;
use crate::text::json_text;
use crate::{HttpSettings, TenantLabel};

/// The platform's identifier.
pub const PLATFORM: &str = "splunk";

/// The management port when the tenant names none.
pub const DEFAULT_PORT: &str = "8089";

/// The warning of a parse a gateway timed out: the query is assumed valid
/// (`PARSER_TIMEOUT_WARNING`).
pub const PARSER_TIMEOUT_WARNING: &str =
    "Splunk's parser timed out behind a gateway; the query is assumed valid";

/// The settings a saved search takes only once the others are set
/// (`_apply_saved_search`'s second stage), in the order they are sent.
pub const SECOND_STAGE: [&str; 4] = ["alert.suppress", "is_scheduled", "actions", "search"];

/// The HTTP settings of a Splunk tenant: *timeout* on connecting and on
/// each read, and the connectors' retries.
pub fn http_settings(timeout: Duration) -> HttpSettings {
    HttpSettings {
        timeout,
        retry: crate::retry::RetryPolicy::standard(),
        ..HttpSettings::default()
    }
}

/// One answer of the management port, an HTML page already refused.
#[derive(Debug)]
struct Reply {
    answer: Answer,
}

impl Reply {
    /// Whether urllib raised `HTTPError` for it: any status outside 2xx.
    fn failed(&self) -> bool {
        !(200..300).contains(&self.answer.status)
    }

    /// The status's reason phrase (`response.msg`).
    fn reason(&self) -> &'static str {
        crate::transport::StatusCode::from_u16(self.answer.status)
            .ok()
            .and_then(|status| status.canonical_reason())
            .unwrap_or("")
    }

    /// What opentide's urllib handler logs for an error status in a client
    /// that raises on it (`request_handler` without `allow_http_errors`:
    /// the deploy's), before the Python Splunk client raises.
    fn log_failure(&self) {
        if self.failed() {
            tracing::error!(
                detail = format!(
                    "Received HTTP Error Code {} {}",
                    self.answer.status,
                    self.reason()
                )
                .as_str(),
                context = format!("{:?}", String::from_utf8_lossy(&self.answer.body)).as_str(),
                critical = true,
                logger = "opentide.platforms.splunk.client",
                "fatal_error"
            );
        }
    }

    /// the Python Splunk client's `HTTPError` text: `HTTP <status> <reason>`, then the
    /// first `<msg>` of an XML error, else the body's bytes.
    fn http_error(&self) -> String {
        let detail = match xml_message(&self.answer.body) {
            XmlDetail::Message(text) => format!(" -- {text}"),
            XmlDetail::None => String::new(),
            XmlDetail::NotXml => {
                format!(" -- {:?}", String::from_utf8_lossy(&self.answer.body))
            }
        };
        format!("HTTP {} {}{detail}", self.answer.status, self.reason())
    }
}

/// What the Python Splunk client's `XML(body).findtext("./messages/msg")` finds.
enum XmlDetail {
    Message(String),
    None,
    NotXml,
}

fn xml_message(body: &[u8]) -> XmlDetail {
    static MSG: OnceLock<Option<regex::Regex>> = OnceLock::new();
    let text = String::from_utf8_lossy(body);
    let trimmed = text.trim_start();
    if !trimmed.starts_with('<') || !trimmed.trim_end().ends_with('>') {
        return XmlDetail::NotXml;
    }
    let found = MSG
        .get_or_init(|| {
            regex::Regex::new(r"(?s)^(?:<\?xml[^>]*\?>\s*)?<[A-Za-z][^>]*>\s*<messages>\s*<msg\b[^>]*>(.*?)</msg>").ok()
        })
        .as_ref()
        .and_then(|pattern| pattern.captures(trimmed))
        .and_then(|captures| captures.get(1));
    match found {
        Some(text) => XmlDetail::Message(xml_unescape(text.as_str())),
        None => XmlDetail::None,
    }
}

/// XML's character references and the five named entities, unescaped.
pub fn xml_unescape(text: &str) -> String {
    if !text.contains('&') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let Some(end) = tail.find(';') else {
            out.push_str(tail);
            return out;
        };
        let name = &tail[1..end];
        let replaced = match name {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => name
                .strip_prefix("#x")
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| name.strip_prefix('#').and_then(|dec| dec.parse().ok()))
                .and_then(char::from_u32),
        };
        match replaced {
            Some(character) => {
                out.push(character);
                rest = &tail[end + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The entries of an Atom feed, each as its raw XML.
fn entries(body: &[u8]) -> Vec<String> {
    static ENTRY: OnceLock<Option<regex::Regex>> = OnceLock::new();
    let text = String::from_utf8_lossy(body);
    ENTRY
        .get_or_init(|| regex::Regex::new(r"(?s)<entry\b.*?</entry>").ok())
        .as_ref()
        .map(|pattern| {
            pattern
                .find_iter(&text)
                .map(|found| found.as_str().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// The value of the content key *name* of an entry, unescaped.
fn content_key(entry: &str, name: &str) -> Option<String> {
    let open = format!("<s:key name=\"{name}\">");
    let start = entry.find(&open)? + open.len();
    let end = entry[start..].find("</s:key>")? + start;
    Some(xml_unescape(&entry[start..end]))
}

/// The `alternate` link of an entry (`state.links.alternate`), unescaped.
fn alternate(entry: &str) -> Option<String> {
    static LINK: OnceLock<Option<regex::Regex>> = OnceLock::new();
    static ATTRIBUTE: OnceLock<Option<regex::Regex>> = OnceLock::new();
    let link = LINK
        .get_or_init(|| regex::Regex::new(r"<link\b[^>]*>").ok())
        .as_ref()?;
    let attribute = ATTRIBUTE
        .get_or_init(|| regex::Regex::new(r#"([A-Za-z:]+)="([^"]*)""#).ok())
        .as_ref()?;
    link.find_iter(entry).find_map(|tag| {
        let attributes: BTreeMap<&str, &str> = attribute
            .captures_iter(tag.as_str())
            .filter_map(|captures| Some((captures.get(1)?.as_str(), captures.get(2)?.as_str())))
            .collect();
        (attributes.get("rel") == Some(&"alternate"))
            .then(|| attributes.get("href").map(|href| xml_unescape(href)))
            .flatten()
    })
}

/// `urllib.parse.unquote`: `%XX` escapes decoded as UTF-8.
fn unquote(text: &str) -> String {
    percent_encoding::percent_decode_str(text)
        .decode_utf8_lossy()
        .into_owned()
}

/// An entity's path without its namespace (`_entity_path`): the link's,
/// unquoted, after `servicesNS/<owner>/<app>/` or `services/`.
fn entity_path(link: &str) -> String {
    let raw = unquote(link);
    if let Some(at) = raw.find("servicesNS/") {
        let rest = &raw[at + "servicesNS/".len()..];
        let mut parts = rest.splitn(3, '/');
        let (_, _, tail) = (parts.next(), parts.next(), parts.next());
        return tail.unwrap_or_default().to_owned();
    }
    if let Some(at) = raw.find("services/") {
        return raw[at + "services/".len()..].to_owned();
    }
    raw
}

/// A saved search the tenant holds (the Python Splunk client's `SavedSearch`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedSearch {
    /// Its path under the namespace, unquoted (`saved/searches/<name>`).
    pub path: String,
    /// Its search as the tenant answered it (`content.search`).
    pub search: Option<String>,
}

impl SavedSearch {
    fn from_entry(entry: &str) -> Option<Self> {
        Some(Self {
            path: entity_path(&alternate(entry)?),
            search: content_key(entry, "search"),
        })
    }
}

/// *query* as Splunk runs it: a query that does not start with a command
/// searches (`spl_search`).
pub fn spl_search(query: &str) -> String {
    let text = query.trim();
    if text.starts_with('|') || text.to_lowercase().starts_with("search ") {
        return text.to_owned();
    }
    format!("search {text}")
}

/// `_parse`: the body as a JSON object; a body that is not JSON is one
/// `ERROR` message holding its text, an empty one `{}`.
fn parse(body: &[u8]) -> Object {
    let text = String::from_utf8_lossy(body);
    if text.is_empty() {
        return Object::new();
    }
    match serde_json::from_str::<Json>(&text) {
        Ok(Json::Object(object)) => object,
        Ok(_) => Object::new(),
        Err(_) => {
            let mut message = Object::new();
            message.insert("type".into(), Json::Str("ERROR".into()));
            message.insert("text".into(), Json::Str(text.into_owned()));
            let mut object = Object::new();
            object.insert("messages".into(), Json::Array(vec![Json::Object(message)]));
            object
        }
    }
}

/// `_messages`: the texts of the messages of the *kinds*, joined by `; `.
fn messages(body: &Object, kinds: &[&str]) -> String {
    let Some(Json::Array(items)) = body.get("messages") else {
        return String::new();
    };
    items
        .iter()
        .filter_map(Json::as_object)
        .filter(|message| {
            let kind = message.get("type").map(json_text).unwrap_or_default();
            kinds.contains(&kind.to_uppercase().as_str())
        })
        .map(|message| message.get("text").map(json_text).unwrap_or_default())
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// A form value as `urlencode` writes Python's value: `str(value)`.
fn form_value(value: &Json) -> String {
    json_text(value)
}

/// `_encode`: the pairs, a list as one pair per item.
fn form(pairs: &[(String, Json)]) -> String {
    let mut flat: Vec<(String, String)> = Vec::new();
    for (key, value) in pairs {
        match value {
            Json::Array(items) => {
                flat.extend(items.iter().map(|item| (key.clone(), form_value(item))));
            }
            other => flat.push((key.clone(), form_value(other))),
        }
    }
    urlencode(
        flat.iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    )
}

/// The Splunk connector. A tenant's search endpoints (v1 or v2) are read
/// from `server/info` once per tenant and kind of client, as the Python Splunk client reads
/// them once per `Service` (the runner keeps one for searches and one for
/// the parser).
#[derive(Debug, Default)]
pub struct Splunk {
    v2: Mutex<BTreeMap<(TenantLabel, &'static str), bool>>,
}

impl Splunk {
    /// A connector that has read no tenant's version yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// `https://<url>:<port>`.
    fn authority(cx: TenantContext<'_>) -> Result<String, ConnectorError> {
        let host = cx.tenant.secret("url")?.expose().trim().to_owned();
        let port = match cx.tenant.setup.get("port") {
            Some(_) => cx.tenant.secret("port")?.expose().trim().to_owned(),
            None => DEFAULT_PORT.to_owned(),
        };
        let port: u16 = port.parse().map_err(|_| ConnectorError::Setup {
            platform: PLATFORM.into(),
            tenant: cx.tenant.label.tenant.clone(),
            message: format!("port must be a number, got {port:?}"),
        })?;
        Ok(format!("https://{host}:{port}"))
    }

    /// The app's namespace (`/servicesNS/nobody/<app>/`).
    fn namespace(cx: TenantContext<'_>) -> Result<String, ConnectorError> {
        let app = match cx.tenant.setup.get("app") {
            Some(_) => cx.tenant.secret("app")?.expose().to_owned(),
            None => "search".to_owned(),
        };
        Ok(format!("/servicesNS/nobody/{}/", quote_plus(&app)))
    }

    /// One request through the urllib handler: the answer, or the error an
    /// HTML page in its place is (`request_handler`).
    async fn send(
        cx: TenantContext<'_>,
        method: crate::transport::Method,
        path: &str,
        body: Option<String>,
    ) -> Result<Reply, ConnectorError> {
        let token = cx.tenant.secret("token")?.expose();
        let authorization = if token.starts_with("Splunk ") {
            token.to_owned()
        } else {
            format!("Splunk {token}")
        };
        let url = format!("{}{path}", Self::authority(cx)?);
        let mut builder = cx
            .http
            .request(method, &url)
            .header("Authorization", authorization);
        if let Some(body) = body {
            builder = builder
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body);
        }
        let answer = crate::answer::exchange(cx, builder).await?;
        if looks_like_html(&answer) {
            return Err(html_answer(cx, &url, &answer));
        }
        Ok(Reply { answer })
    }

    /// Whether the tenant's search endpoints are v2 (`not disable_v2_api`):
    /// `server/info` read twice, for the instance type and the version.
    async fn search_v2(
        &self,
        cx: TenantContext<'_>,
        kind: &'static str,
    ) -> Result<bool, ConnectorError> {
        let key = (cx.tenant.label.clone(), kind);
        if let Some(v2) = self
            .v2
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
        {
            return Ok(*v2);
        }
        let info = |reply: &Reply| -> Result<String, ConnectorError> {
            if reply.failed() {
                return Err(ConnectorError::refused(
                    PLATFORM,
                    &cx.tenant.label.tenant,
                    format!(
                        "Splunk did not answer server/info on {} (HTTP {})",
                        cx.tenant.label.tenant, reply.answer.status
                    ),
                    Some(reply.http_error()),
                ));
            }
            Ok(entries(&reply.answer.body)
                .into_iter()
                .next()
                .unwrap_or_default())
        };
        let first = Self::send(
            cx,
            crate::transport::Method::GET,
            "/services/server/info",
            None,
        )
        .await?;
        let instance = content_key(&info(&first)?, "instance_type").unwrap_or_default();
        let second = Self::send(
            cx,
            crate::transport::Method::GET,
            "/services/server/info",
            None,
        )
        .await?;
        let version = content_key(&info(&second)?, "version").unwrap_or_default();
        let parsed: Option<Vec<u64>> = version.split('.').map(|part| part.parse().ok()).collect();
        let Some(parsed) = parsed else {
            return Err(ConnectorError::refused(
                PLATFORM,
                &cx.tenant.label.tenant,
                format!(
                    "Splunk on {} answered server/info with the version {version:?}",
                    cx.tenant.label.tenant
                ),
                None,
            ));
        };
        let floor: &[u64] = if instance.to_lowercase() == "cloud" {
            &[9, 0, 2209]
        } else {
            &[9, 0, 2]
        };
        let v2 = parsed.as_slice() >= floor;
        self.v2
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, v2);
        Ok(v2)
    }

    /// The saved search *name*, or `None` when the tenant answers 404 or no
    /// entry (`saved_searches[name]` raising `KeyError`).
    pub async fn saved_search(
        &self,
        cx: TenantContext<'_>,
        name: &str,
    ) -> Result<Option<SavedSearch>, ConnectorError> {
        let path = format!(
            "{}saved/searches/{}",
            Self::namespace(cx)?,
            quote_plus(name)
        );
        let reply = Self::send(cx, crate::transport::Method::GET, &path, None).await?;
        reply.log_failure();
        if reply.answer.status == 404 {
            return Ok(None);
        }
        if reply.failed() {
            return Err(refused_call(cx, &reply));
        }
        let found = entries(&reply.answer.body);
        if found.len() > 1 {
            return Err(ConnectorError::refused(
                PLATFORM,
                &cx.tenant.label.tenant,
                format!(
                    "Found multiple entities named '{}'; please specify a namespace.",
                    quote_plus(name)
                ),
                None,
            ));
        }
        Ok(found
            .first()
            .and_then(|entry| SavedSearch::from_entry(entry)))
    }

    /// Creates the saved search *name* running *search*
    /// (`saved_searches.create`).
    pub async fn create_saved_search(
        &self,
        cx: TenantContext<'_>,
        name: &str,
        search: &str,
    ) -> Result<SavedSearch, ConnectorError> {
        let path = format!("{}saved/searches/", Self::namespace(cx)?);
        let body = urlencode([("name", name), ("search", search)]);
        let reply = Self::send(cx, crate::transport::Method::POST, &path, Some(body)).await?;
        reply.log_failure();
        if reply.failed() {
            return Err(refused_call(cx, &reply));
        }
        match entries(&reply.answer.body)
            .first()
            .and_then(|entry| SavedSearch::from_entry(entry))
        {
            Some(created) => Ok(created),
            None => self.saved_search(cx, name).await?.ok_or_else(|| {
                ConnectorError::refused(
                    PLATFORM,
                    &cx.tenant.label.tenant,
                    format!("Splunk created no saved search named {name:?}"),
                    None,
                )
            }),
        }
    }

    /// Sets *settings* on *saved* (`SavedSearch.update`): its `search` first
    /// (the one given, else the one the tenant answered), then the others in
    /// order.
    pub async fn update_saved_search(
        &self,
        cx: TenantContext<'_>,
        saved: &SavedSearch,
        settings: &Object,
    ) -> Result<(), ConnectorError> {
        let search = settings
            .get("search")
            .cloned()
            .or_else(|| saved.search.clone().map(Json::Str))
            .unwrap_or(Json::Null);
        let mut pairs = vec![("search".to_owned(), search)];
        pairs.extend(
            settings
                .iter()
                .filter(|(key, _)| key.as_str() != "search")
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        let path = format!("{}{}", Self::namespace(cx)?, quote(&saved.path, "/"));
        let reply = Self::send(
            cx,
            crate::transport::Method::POST,
            &path,
            Some(form(&pairs)),
        )
        .await?;
        reply.log_failure();
        if reply.failed() {
            return Err(refused_call(cx, &reply));
        }
        Ok(())
    }

    /// Deletes the saved search *name* (`saved_searches.delete`).
    pub async fn delete_saved_search(
        &self,
        cx: TenantContext<'_>,
        name: &str,
    ) -> Result<(), ConnectorError> {
        let path = format!(
            "{}saved/searches/{}",
            Self::namespace(cx)?,
            quote_plus(name)
        );
        let reply = Self::send(cx, crate::transport::Method::DELETE, &path, None).await?;
        reply.log_failure();
        if reply.failed() {
            return Err(refused_call(cx, &reply));
        }
        Ok(())
    }

    /// Writes the saved search *name* with *settings*
    /// (`_apply_saved_search`): its settings, actions and `search`, as the
    /// deployer compiles them. Looked up first; created when missing; with
    /// *deletion*, deleted instead (nothing when it is already gone). The
    /// settings Splunk takes only once the others are set
    /// ([`SECOND_STAGE`]) go in a second update. `Some(true)` when the saved
    /// search was written, `None` when it was deleted or already absent.
    pub async fn apply_saved_search(
        &self,
        cx: TenantContext<'_>,
        name: &str,
        settings: &Object,
        deletion: bool,
    ) -> Result<Option<bool>, ConnectorError> {
        let mut first = settings.clone();
        let mut second = Object::new();
        for key in SECOND_STAGE {
            if let Some(value) = first.shift_remove(key) {
                second.insert(key.into(), value);
            }
        }
        let query = settings.get("search").map(json_text).unwrap_or_default();
        let saved = match self.saved_search(cx, name).await? {
            Some(saved) => saved,
            None if deletion => return Ok(None),
            None => self.create_saved_search(cx, name, &query).await?,
        };
        if deletion {
            self.delete_saved_search(cx, name).await?;
            return Ok(None);
        }
        self.update_saved_search(cx, &saved, &first).await?;
        if !second.is_empty() {
            self.update_saved_search(cx, &saved, &second).await?;
        }
        Ok(Some(true))
    }

    /// Runs *request* as a one-shot search (`SplunkQueryRunner.run`): epoch
    /// seconds for the window, one row more than the limit, JSON rows.
    pub async fn run(
        &self,
        cx: TenantContext<'_>,
        request: &QueryRequest,
    ) -> Result<QueryOutcome, ConnectorError> {
        let tenant = cx.tenant.label.tenant.clone();
        let sent = spl_search(&request.text);
        let v2 = self.search_v2(cx, "search").await?;
        let path = format!(
            "{}{}",
            Self::namespace(cx)?,
            if v2 {
                "search/v2/jobs/"
            } else {
                "search/jobs/"
            }
        );
        let earliest = epoch(request.window.start);
        let latest = epoch(request.window.end);
        let count = request.limit.saturating_add(1).to_string();
        let body = urlencode([
            ("search", sent.as_str()),
            ("exec_mode", "oneshot"),
            ("earliest_time", earliest.as_str()),
            ("latest_time", latest.as_str()),
            ("count", count.as_str()),
            ("output_mode", "json"),
            ("segmentation", "none"),
        ]);
        let reply = Self::send(cx, crate::transport::Method::POST, &path, Some(body)).await?;
        if reply.failed() {
            let found = messages(&parse(&reply.answer.body), &["ERROR", "FATAL"]);
            let detail = if found.is_empty() {
                reply.http_error()
            } else {
                found
            };
            return Err(ConnectorError::refused(
                PLATFORM,
                &tenant,
                format!(
                    "Splunk refused the search on {tenant} (HTTP {})",
                    reply.answer.status
                ),
                Some(detail),
            ));
        }
        let body = parse(&reply.answer.body);
        let errors = messages(&body, &["ERROR", "FATAL"]);
        if !errors.is_empty() {
            return Err(ConnectorError::refused(
                PLATFORM,
                &tenant,
                format!("Splunk refused the search on {tenant}"),
                Some(errors),
            ));
        }
        let rows: Vec<Row> = match body.get("results") {
            Some(Json::Array(items)) => items.iter().filter_map(Json::as_object).cloned().collect(),
            _ => Vec::new(),
        };
        let names: Vec<String> = match body.get("fields") {
            Some(Json::Array(fields)) => fields
                .iter()
                .filter_map(|field| field.get("name"))
                .filter_map(|name| name.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        };
        let columns = if names.is_empty() {
            columns_of(&rows)
        } else {
            names.into_iter().map(QueryColumn::named).collect()
        };
        let warning = messages(&body, &["WARN"]);
        let truncated = rows.len() > request.limit;
        Ok(QueryOutcome {
            columns,
            rows: rows.into_iter().take(request.limit).collect(),
            truncated,
            partial: false,
            warnings: if warning.is_empty() {
                Vec::new()
            } else {
                vec![warning]
            },
            vendor_query_id: None,
            sent: (sent != request.text.trim()).then_some(sent),
            language: Some("spl".into()),
        })
    }

    /// Splunk's `search/parser` (`SplunkQueryRunner.check`): the query is
    /// parsed with its macros and lookups, no search job runs. A refusal is
    /// [`ConnectorError::Refused`]; the gateway's 307 `Network Error` passes
    /// with [`PARSER_TIMEOUT_WARNING`].
    pub async fn check(
        &self,
        cx: TenantContext<'_>,
        request: &QueryRequest,
    ) -> Result<LiveCheck, ConnectorError> {
        let tenant = cx.tenant.label.tenant.clone();
        let mut query = request.text.trim().to_owned();
        if !query.starts_with("| ") {
            query = format!("| search {query}");
        }
        let query = query.trim();
        let v2 = self.search_v2(cx, "parser").await?;
        let form = urlencode([
            ("q", query),
            ("enable_lookups", "True"),
            ("output_mode", "json"),
            ("reload_macros", "True"),
        ]);
        let namespace = Self::namespace(cx)?;
        let reply = if v2 {
            let path = format!("{namespace}search/v2/parser");
            Self::send(cx, crate::transport::Method::POST, &path, Some(form)).await?
        } else {
            let path = format!("{namespace}search/parser?{form}");
            Self::send(cx, crate::transport::Method::GET, &path, None).await?
        };
        let status = reply.answer.status;
        if reply.failed() {
            let body = &reply.answer.body;
            if reply.reason() == "Temporary Redirect"
                && String::from_utf8_lossy(body).contains("Network Error")
            {
                return Ok(LiveCheck {
                    result: None,
                    errors: Vec::new(),
                    warnings: vec![PARSER_TIMEOUT_WARNING.into()],
                });
            }
            if matches!(status, 502..=504)
                && serde_json::from_str::<Json>(&String::from_utf8_lossy(body)).is_err()
            {
                return Err(ConnectorError::Gateway {
                    platform: PLATFORM.into(),
                    tenant: tenant.clone(),
                    message: format!(
                        "Splunk's parser did not answer on {tenant}: {}",
                        describe_answer(status, body, None, None)
                    ),
                    status,
                });
            }
            let all = all_messages(&parse(body));
            return Err(ConnectorError::refused(
                PLATFORM,
                &tenant,
                format!("Splunk refused the query on {tenant}"),
                (!all.is_empty()).then_some(all),
            ));
        }
        // Another 2xx is neither a refusal nor an acceptance: Python logs it
        // (`unexpected_splunk_validation_response`) and passes the query.
        Ok(LiveCheck::default())
    }
}

/// Every message's text, whatever its type, joined by `; ` (the parser's
/// refusal).
fn all_messages(body: &Object) -> String {
    let Some(Json::Array(items)) = body.get("messages") else {
        return String::new();
    };
    items
        .iter()
        .filter_map(Json::as_object)
        .map(|message| message.get("text").map(json_text).unwrap_or_default())
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// *at* in epoch seconds with three decimals (`f"{timestamp():.3f}"`).
fn epoch(at: jiff::Timestamp) -> String {
    #[expect(
        clippy::cast_precision_loss,
        reason = "Python formats the float timestamp() the same way"
    )]
    let seconds = at.as_second() as f64 + f64::from(at.subsec_nanosecond()) / 1e9;
    format!("{seconds:.3}")
}

/// A saved search call the tenant refused (the Python Splunk client's `HTTPError`).
fn refused_call(cx: TenantContext<'_>, reply: &Reply) -> ConnectorError {
    ConnectorError::refused(
        PLATFORM,
        &cx.tenant.label.tenant,
        reply.http_error(),
        Some(format!(
            "Received HTTP Error Code {} {}",
            reply.answer.status,
            reply.reason()
        )),
    )
}

/// An HTML page, which the REST API never sends (`_looks_like_html`): a
/// body labelled XML, JSON or text is trusted whatever it starts with.
fn looks_like_html(answer: &Answer) -> bool {
    let kind = answer
        .content_type
        .as_deref()
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if kind == "text/html" {
        return true;
    }
    if !kind.is_empty() {
        return false;
    }
    let trimmed = answer.body.trim_ascii_start();
    let head = trimmed[..trimmed.len().min(15)].to_ascii_lowercase();
    head.starts_with(b"<!doctype html") || head.starts_with(b"<html")
}

/// The error an HTML page answering *url* is (`_html_answer`): a gateway's
/// ([`ConnectorError::Gateway`]: one query timed out), else a proxy's or a
/// wrong port's ([`ConnectorError::Unreachable`]).
fn html_answer(cx: TenantContext<'_>, url: &str, answer: &Answer) -> ConnectorError {
    let parsed = url::Url::parse(url).ok();
    let origin = parsed
        .as_ref()
        .map(crate::error::origin)
        .unwrap_or_default();
    let page = page_title(&answer.body)
        .map(|title| format!(" (page title: {title:?})"))
        .unwrap_or_default();
    let answered = format!(
        "Splunk at {origin} answered with an HTML page (HTTP {}), not its REST API{page}",
        answer.status
    );
    let proxy = parsed.as_ref().and_then(|url| cx.http.route(url));
    if let Some(gateway) = gateway_answer(answer.status, Some(answer.elapsed)) {
        let through = proxy
            .as_ref()
            .map(|proxy| format!(" The request went through the proxy {proxy}."))
            .unwrap_or_default();
        let mut characters = gateway.chars();
        let capitalised: String = characters
            .next()
            .map(|first| first.to_uppercase().chain(characters).collect())
            .unwrap_or_default();
        return ConnectorError::Gateway {
            platform: PLATFORM.into(),
            tenant: cx.tenant.label.tenant.clone(),
            message: format!(
                "{answered}. {capitalised}.{through} The request may be too slow for the \
                 gateway: make the query cheaper, or raise the gateway's timeout."
            ),
            status: answer.status,
        };
    }
    let reason = match proxy {
        Some(proxy) => {
            let host = parsed
                .as_ref()
                .and_then(|url| url.host_str().map(str::to_owned))
                .unwrap_or_default();
            format!(
                "{answered}. The request went through the proxy {proxy}, so the page is most \
                 likely the proxy's (a block or sign-in page). If this tenant is reached \
                 directly, add its host to NO_PROXY and no_proxy (NO_PROXY={host}); otherwise \
                 check the tenant's port: 8089 is the REST API, 8000 Splunk Web."
            )
        }
        None => format!(
            "{answered}. Check the tenant's url and port: the REST API listens on the \
             management port (8089 by default), while 8000 serves Splunk Web."
        ),
    };
    ConnectorError::Unreachable {
        platform: PLATFORM.into(),
        tenant: cx.tenant.label.tenant.clone(),
        address: origin,
        reason,
    }
}

impl Deployer for Splunk {
    /// The saved search `rule_id` with the compiled settings in `body` (a
    /// JSON object: the rule's settings, its actions and `search`), through
    /// [`Splunk::apply_saved_search`]; a delete removes it.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        Box::pin(async move {
            let settings = match serde_json::from_slice::<Json>(&request.body) {
                Ok(Json::Object(settings)) => settings,
                Ok(_) | Err(_) if request.operation == Operation::Delete => Object::new(),
                _ => {
                    return Err(ConnectorError::Setup {
                        platform: PLATFORM.into(),
                        tenant: cx.tenant.label.tenant.clone(),
                        message: "the compiled saved search is not a JSON object".into(),
                    });
                }
            };
            let deletion = request.operation == Operation::Delete;
            self.apply_saved_search(cx, &request.rule_id, &settings, deletion)
                .await?;
            Ok(DeployOutcome {
                remote_id: (!deletion).then(|| request.rule_id.clone()),
                operation: request.operation,
            })
        })
    }
}

impl QueryRunner for Splunk {
    /// A one-shot search over the request's window.
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        Box::pin(Splunk::run(self, cx, request))
    }
}

impl LiveValidator for Splunk {
    /// Splunk's parser: no search runs.
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        Box::pin(self.check(cx, request))
    }
}

impl Platform for Splunk {
    fn id(&self) -> &'static str {
        PLATFORM
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self)
    }

    fn live_validator(&self) -> Option<&dyn LiveValidator> {
        Some(self)
    }

    fn query_runner(&self) -> Option<&dyn QueryRunner> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_search_unless_they_start_with_a_command() {
        assert_eq!(spl_search(" index=main "), "search index=main");
        assert_eq!(spl_search("| tstats count"), "| tstats count");
        assert_eq!(spl_search("SEARCH x"), "SEARCH x");
    }

    #[test]
    fn atom_entries_read_as_the_python_client_reads_them() {
        let feed = br#"<feed><entry><title>a b</title><link href="/servicesNS/nobody/search/saved/searches/a%20b" rel="alternate"/><content type="text/xml"><s:dict><s:key name="search">index=x &amp; y &lt;z&gt;</s:key></s:dict></content></entry></feed>"#;
        let found = entries(feed);
        assert_eq!(
            SavedSearch::from_entry(&found[0]),
            Some(SavedSearch {
                path: "saved/searches/a b".into(),
                search: Some("index=x & y <z>".into()),
            })
        );
        assert_eq!(xml_unescape("&#233;&#xe9;&bogus;"), "éé&bogus;");
    }

    #[test]
    fn errors_quote_the_first_message_else_the_bytes() {
        let reply = |status, body: &[u8]| Reply {
            answer: Answer {
                status,
                content_type: None,
                body: body.to_vec(),
                elapsed: Duration::ZERO,
            },
        };
        assert_eq!(reply(404, b"").http_error(), "HTTP 404 Not Found -- \"\"");
        assert_eq!(
            reply(
                400,
                b"<response><messages><msg type=\"ERROR\">Argument &quot;x&quot;</msg></messages></response>"
            )
            .http_error(),
            "HTTP 400 Bad Request -- Argument \"x\""
        );
        assert_eq!(
            reply(400, b"{\"a\": 1}").http_error(),
            "HTTP 400 Bad Request -- \"{\\\"a\\\": 1}\""
        );
        assert_eq!(
            epoch("2026-10-27T08:00:00.25Z".parse().unwrap()),
            "1793088000.250"
        );
    }
}
