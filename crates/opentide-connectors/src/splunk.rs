//! Splunk's management API (UC-4.3, #833): the saved searches deploy writes
//! (`_apply_saved_search`), the one-shot searches of `opentide query`, the
//! `search/parser` check (`validate query --live`), and the `server/info`
//! reads that choose between the v1 and v2 search endpoints.
//!
//! Every call carries `Authorization: Splunk <token>` (the token as is when
//! it already starts with `Splunk `); a body is a form, with
//! `Content-Type: application/x-www-form-urlencoded`. The tenant is
//! `https://<url>:<port>`, and every path but `server/info` is under the
//! app's namespace (`/servicesNS/nobody/<app>/`). An HTML page in place of
//! the API's answer is a gateway's or a proxy's (`_html_answer`).

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use opentide_compile::json::{Json, Object};

use crate::answer::{Answer, describe_answer, gateway_answer, page_title};
use crate::connector::{
    BoxFuture, DeployError, DeployFailure, DeployOutcome, DeployRequest, DeployWarning, Deployer,
    LiveCheck, LiveValidator, Operation, Platform, QueryColumn, QueryOutcome, QueryRequest,
    QueryRunner, Row, TenantContext, columns_of,
};
use crate::error::ConnectorError;
use crate::text::json_text;
use crate::{HttpSettings, TenantLabel};
use opentide_compile::deploy::PATH_SEGMENT;
use percent_encoding::utf8_percent_encode;
use url::form_urlencoded::byte_serialize;

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
    /// Whether the status is outside 2xx.
    fn failed(&self) -> bool {
        !(200..300).contains(&self.answer.status)
    }

    /// Logs an error status as a warning: deploy reads the answer on. A
    /// `404` for a saved search that is not there is no failure, and its
    /// caller logs it at debug instead.
    fn log_failure(&self) {
        if self.failed() {
            tracing::warn!(status = self.answer.status, "{}", self.http_error());
        }
    }

    /// `Splunk answered HTTP <status> <reason>`, then the first `<msg>` of an
    /// XML error, else the body's text when there is one.
    /// A failed search's detail: its `ERROR` and `FATAL` messages, else
    /// [`http_error`](Self::http_error), read from the masked text.
    fn search_refusal(&self) -> String {
        let found = messages(&parse(self.answer.text().as_bytes()), &["ERROR", "FATAL"]);
        if found.is_empty() {
            self.http_error()
        } else {
            found
        }
    }

    /// A searched answer's `ERROR` and `FATAL` messages, masked: a body
    /// that is not JSON is one message holding its text.
    fn search_errors(&self, body: &Object) -> String {
        self.answer
            .credentials
            .mask_text(&messages(body, &["ERROR", "FATAL"]))
    }

    /// What a failed parser check is (`_validate`), read from the masked
    /// text: a 307 "Network Error" is the parser's timeout, a 502 to 504
    /// that is not JSON a gateway's, a 401 the credential's, anything else a
    /// refusal.
    fn check_failure(&self, tenant: &str) -> Result<LiveCheck, ConnectorError> {
        let status = self.answer.status;
        let text = self.answer.text();
        if status == 307 && text.contains("Network Error") {
            return Ok(LiveCheck {
                result: None,
                errors: Vec::new(),
                warnings: vec![PARSER_TIMEOUT_WARNING.into()],
            });
        }
        if matches!(status, 502..=504) && serde_json::from_str::<Json>(&text).is_err() {
            return Err(ConnectorError::Gateway {
                platform: PLATFORM.into(),
                tenant: tenant.to_owned(),
                message: format!(
                    "Splunk's parser did not answer on {tenant}: {}",
                    describe_answer(status, text.as_bytes(), None, None)
                ),
                status,
            });
        }
        let all = all_messages(&parse(text.as_bytes()));
        if status == 401 {
            // The credential, not the query: no query was checked (#1658, E8).
            let reason = if all.is_empty() {
                String::new()
            } else {
                format!(": {all}")
            };
            return Err(ConnectorError::authentication(
                PLATFORM,
                tenant,
                format!("Splunk refused the credential (HTTP 401){reason}"),
            ));
        }
        Err(ConnectorError::refused(
            PLATFORM,
            tenant,
            format!("Splunk refused the query on {tenant}"),
            (!all.is_empty()).then_some(all),
        ))
    }

    fn http_error(&self) -> String {
        let status = self.answer.status;
        let reason = crate::transport::StatusCode::from_u16(status)
            .ok()
            .and_then(|status| status.canonical_reason())
            .map(|reason| format!(" {reason}"))
            .unwrap_or_default();
        // Masked text: a message the API wrote may echo the token.
        let detail = match xml_message(self.answer.text().as_bytes()) {
            XmlDetail::Message(text) => text,
            XmlDetail::None => String::new(),
            XmlDetail::NotXml => self.answer.text().trim().to_owned(),
        };
        if detail.is_empty() {
            format!("Splunk answered HTTP {status}{reason}")
        } else {
            format!("Splunk answered HTTP {status}{reason}: {detail}")
        }
    }
}

/// The first `./messages/msg` of an XML error body.
enum XmlDetail {
    Message(String),
    None,
    NotXml,
}

fn xml_message(body: &[u8]) -> XmlDetail {
    let text = String::from_utf8_lossy(body);
    let trimmed = text.trim_start();
    if !trimmed.starts_with('<') || !trimmed.trim_end().ends_with('>') {
        return XmlDetail::NotXml;
    }
    // XML that does not parse is read as no message, as a page of HTML is.
    let Ok(document) = roxmltree::Document::parse(trimmed) else {
        return XmlDetail::None;
    };
    let message = first_element(document.root_element())
        .filter(|messages| messages.has_tag_name("messages"))
        .and_then(first_element)
        .filter(|msg| msg.has_tag_name("msg"));
    match message {
        Some(msg) => XmlDetail::Message(text_of(msg)),
        None => XmlDetail::None,
    }
}

/// The first element inside *node*.
fn first_element<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
) -> Option<roxmltree::Node<'a, 'input>> {
    node.children().find(roxmltree::Node::is_element)
}

/// The text inside *node*, character references unescaped.
fn text_of(node: roxmltree::Node<'_, '_>) -> String {
    node.descendants()
        .filter(roxmltree::Node::is_text)
        .filter_map(|text| text.text())
        .collect()
}

/// An entry of an Atom feed: what the saved-search and `server/info`
/// answers are read from.
#[derive(Debug, Default)]
struct Entry {
    /// Its `alternate` link (`state.links.alternate`).
    alternate: Option<String>,
    /// The `s:key`s of its content, by name: the first of a name wins.
    keys: Vec<(String, String)>,
}

impl Entry {
    fn read(entry: roxmltree::Node<'_, '_>) -> Self {
        let mut read = Self::default();
        for node in entry.descendants().filter(roxmltree::Node::is_element) {
            match node.tag_name().name() {
                "link"
                    if read.alternate.is_none() && node.attribute("rel") == Some("alternate") =>
                {
                    read.alternate = node.attribute("href").map(str::to_owned);
                }
                "key" => {
                    if let Some(name) = node.attribute("name") {
                        read.keys.push((name.to_owned(), text_of(node)));
                    }
                }
                _ => {}
            }
        }
        read
    }

    /// The value of the content key *name*.
    fn key(&self, name: &str) -> Option<String> {
        self.keys
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }
}

/// The entries of an Atom feed; a body that is not XML has none.
fn entries(body: &[u8]) -> Vec<Entry> {
    let text = String::from_utf8_lossy(body);
    let Ok(document) = roxmltree::Document::parse(&text) else {
        return Vec::new();
    };
    document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "entry")
        .map(Entry::read)
        .collect()
}

/// An entity's path without its namespace (`_entity_path`): the link's,
/// percent-decoded, after `servicesNS/<owner>/<app>/` or `services/`.
fn entity_path(link: &str) -> String {
    let raw = percent_encoding::percent_decode_str(link)
        .decode_utf8_lossy()
        .into_owned();
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

/// A saved search's name as the last segment of its path. Splunk decodes
/// the segment as a form value (`+` is a space), as its own clients write
/// it.
fn entity_name(name: &str) -> String {
    byte_serialize(name.as_bytes()).collect()
}

/// A saved search the tenant holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedSearch {
    /// Its path under the namespace, percent-decoded (`saved/searches/<name>`).
    pub path: String,
    /// Its search as the tenant answered it (`content.search`).
    pub search: Option<String>,
}

impl SavedSearch {
    fn from_entry(entry: &Entry) -> Option<Self> {
        Some(Self {
            path: entity_path(entry.alternate.as_deref()?),
            search: entry.key("search"),
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

/// A form of *pairs*, a list as one field per item and any other value as
/// its text ([`json_text`]).
fn form(pairs: &[(String, Json)]) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        match value {
            Json::Array(items) => {
                for item in items {
                    form.append_pair(key, &json_text(item));
                }
            }
            other => {
                form.append_pair(key, &json_text(other));
            }
        }
    }
    form.finish()
}

/// The Splunk connector. A tenant's search endpoints (v1 or v2) are read
/// from `server/info` once per tenant and kind of client (one for searches,
/// one for the parser).
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

    /// The tenant's app (`search` when it names none).
    fn app(cx: TenantContext<'_>) -> Result<String, ConnectorError> {
        Ok(match cx.tenant.setup.get("app") {
            Some(_) => cx.tenant.secret("app")?.expose().to_owned(),
            None => "search".to_owned(),
        })
    }

    /// The app's namespace (`/servicesNS/nobody/<app>/`).
    fn namespace(cx: TenantContext<'_>) -> Result<String, ConnectorError> {
        Ok(format!(
            "/servicesNS/nobody/{}/",
            utf8_percent_encode(&Self::app(cx)?, PATH_SEGMENT)
        ))
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
        let info = |reply: &Reply| -> Result<Entry, ConnectorError> {
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
        let instance = info(&first)?.key("instance_type").unwrap_or_default();
        let second = Self::send(
            cx,
            crate::transport::Method::GET,
            "/services/server/info",
            None,
        )
        .await?;
        let version = info(&second)?.key("version").unwrap_or_default();
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
            entity_name(name)
        );
        let reply = Self::send(cx, crate::transport::Method::GET, &path, None).await?;
        // Not there yet: the normal path to creating it, no failure.
        if reply.answer.status == 404 {
            tracing::debug!(status = reply.answer.status, "{}", reply.http_error());
            return Ok(None);
        }
        reply.log_failure();
        if reply.failed() {
            return Err(refused_call(cx, &reply));
        }
        let found = entries(&reply.answer.body);
        if found.len() > 1 {
            return Err(ConnectorError::refused(
                PLATFORM,
                &cx.tenant.label.tenant,
                format!("Found multiple entities named {name:?}; please specify a namespace."),
                None,
            ));
        }
        Ok(found.first().and_then(SavedSearch::from_entry))
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
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([("name", name), ("search", search)])
            .finish();
        let reply = Self::send(cx, crate::transport::Method::POST, &path, Some(body)).await?;
        reply.log_failure();
        if reply.failed() {
            return Err(refused_call(cx, &reply));
        }
        match entries(&reply.answer.body)
            .first()
            .and_then(SavedSearch::from_entry)
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
        let path = saved
            .path
            .split('/')
            .map(|segment| utf8_percent_encode(segment, PATH_SEGMENT).to_string())
            .collect::<Vec<_>>()
            .join("/");
        let path = format!("{}{path}", Self::namespace(cx)?);
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

    /// The saved searches of the tenant's app, but *keep*, whose
    /// description names the rule *uuid* on its last line
    /// ([`opentide_compile::splunk::described`]): the ones an earlier name of
    /// the rule left (#1657). One listing, narrowed by Splunk's `search`
    /// filter to the UUID, then to the exact marker, the app and its
    /// `nobody` owner here; keyed by the rule's own UUID, so another rule's
    /// saved search is never among them, whatever its name.
    pub async fn other_saved_searches(
        &self,
        cx: TenantContext<'_>,
        uuid: &str,
        keep: &str,
    ) -> Result<Vec<String>, ConnectorError> {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([("search", uuid), ("count", "0")])
            .finish();
        let path = format!("{}saved/searches?{query}", Self::namespace(cx)?);
        let reply = Self::send(cx, crate::transport::Method::GET, &path, None).await?;
        reply.log_failure();
        if reply.failed() {
            return Err(refused_call(cx, &reply));
        }
        let app = Self::app(cx)?;
        Ok(entries(&reply.answer.body)
            .iter()
            .filter(|entry| {
                entry.key("description").is_some_and(|description| {
                    opentide_compile::splunk::marked_rule(&description) == Some(uuid)
                })
            })
            .filter(|entry| entry.key("app").is_none_or(|found| found == app))
            .filter(|entry| entry.key("owner").is_none_or(|owner| owner == "nobody"))
            .filter_map(SavedSearch::from_entry)
            .filter_map(|saved| {
                saved
                    .path
                    .strip_prefix("saved/searches/")
                    .map(str::to_owned)
            })
            .filter(|name| name != keep)
            .collect())
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
            entity_name(name)
        );
        let reply = Self::send(cx, crate::transport::Method::DELETE, &path, None).await?;
        reply.log_failure();
        if reply.failed() {
            return Err(refused_call(cx, &reply));
        }
        Ok(())
    }

    /// [`Deployer::deploy`]: the saved search `request` names written, or
    /// deleted, and a renamed rule's old saved searches deleted.
    async fn deploy_saved_search(
        &self,
        cx: TenantContext<'_>,
        request: &DeployRequest,
    ) -> Result<DeployOutcome, DeployError> {
        let settings = match serde_json::from_slice::<Json>(&request.body) {
            Ok(Json::Object(settings)) => settings,
            Ok(_) | Err(_) if request.operation == Operation::Delete => Object::new(),
            _ => {
                return Err(ConnectorError::Setup {
                    platform: PLATFORM.into(),
                    tenant: cx.tenant.label.tenant.clone(),
                    message: "the compiled saved search is not a JSON object".into(),
                }
                .into());
            }
        };
        let uuid = settings
            .get("description")
            .map(json_text)
            .as_deref()
            .and_then(opentide_compile::splunk::marked_rule)
            .map(str::to_owned);
        let name = &request.rule_id;
        let mut warnings = Vec::new();
        if request.operation == Operation::Delete {
            if self.saved_search(cx, name).await?.is_some() {
                self.delete_saved_search(cx, name).await?;
                // Said, not raised: the run's warnings are for what to check.
                warnings.push(DeployWarning::new("splunk_alert_deleted", name.clone()).unraised());
            }
        } else {
            self.apply_saved_search(cx, name, &settings, false).await?;
        }
        // The saved searches an earlier name of the rule left (a rename,
        // or ` - Rule` added or dropped), found by the rule's UUID on the
        // last line of their description, are deleted once the rule is
        // written under its name now, or retired (#1657). A request whose
        // body names no rule (an SDK's bare delete) looks for none.
        if let Some(uuid) = uuid {
            let done = Done {
                name,
                deleted: request.operation == Operation::Delete,
            };
            let others = match self.other_saved_searches(cx, &uuid, name).await {
                Ok(others) => others,
                Err(error) => {
                    return Err(done.cleanup_failed(None, &error, request.operation, warnings));
                }
            };
            for old in others {
                if let Err(error) = self.delete_saved_search(cx, &old).await {
                    return Err(done.cleanup_failed(
                        Some(&old),
                        &error,
                        request.operation,
                        warnings,
                    ));
                }
                // Said, not raised: what the run did, not what to check.
                warnings.push(DeployWarning::new(RENAMED_DELETED, old).unraised());
            }
        }
        let remote_id = (request.operation != Operation::Delete).then(|| name.clone());
        Ok(DeployOutcome::new(remote_id, request.operation).with_warnings(warnings))
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
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("search", sent.as_str()),
                ("exec_mode", "oneshot"),
                ("earliest_time", earliest.as_str()),
                ("latest_time", latest.as_str()),
                ("count", count.as_str()),
                ("output_mode", "json"),
                ("segmentation", "none"),
            ])
            .finish();
        let reply = Self::send(cx, crate::transport::Method::POST, &path, Some(body)).await?;
        if reply.failed() {
            let detail = reply.search_refusal();
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
        let errors = reply.search_errors(&body);
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
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("q", query),
                ("enable_lookups", "True"),
                ("output_mode", "json"),
                ("reload_macros", "True"),
            ])
            .finish();
        let namespace = Self::namespace(cx)?;
        let reply = if v2 {
            let path = format!("{namespace}search/v2/parser");
            Self::send(cx, crate::transport::Method::POST, &path, Some(form)).await?
        } else {
            let path = format!("{namespace}search/parser?{form}");
            Self::send(cx, crate::transport::Method::GET, &path, None).await?
        };
        if reply.failed() {
            return reply.check_failure(&tenant);
        }
        // Another 2xx is neither a refusal nor an acceptance: the query
        // passes, and nothing is reported (the oracle only logged it, as
        // `unexpected_splunk_validation_response`).
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

/// A saved search call the tenant refused: a 401 refuses the token, so the
/// tenant ([`ConnectorError::Authentication`], #1701); any other status the
/// rule.
fn refused_call(cx: TenantContext<'_>, reply: &Reply) -> ConnectorError {
    call_refusal(&cx.tenant.label.tenant, reply)
}

/// [`refused_call`] on *tenant*.
fn call_refusal(tenant: &str, reply: &Reply) -> ConnectorError {
    if reply.answer.status == 401 {
        return ConnectorError::authentication(PLATFORM, tenant, reply.http_error());
    }
    ConnectorError::refused(PLATFORM, tenant, reply.http_error(), None)
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
    let page = page_title(answer.text().as_bytes())
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

/// The warning of a saved search an earlier name of its rule left, deleted
/// after the rule was written under its name now; its message is the old
/// name.
pub const RENAMED_DELETED: &str = "splunk_renamed_search_deleted";

/// The code of a rule written under its name whose old saved search could
/// not be looked up or deleted.
pub const RENAMED_CLEANUP_FAILED: &str = "splunk_renamed_search_not_deleted";

/// The saved search a deploy wrote (or, with `deleted`, retired) under the
/// rule's name now, before it looked for the ones an earlier name left.
struct Done<'a> {
    name: &'a str,
    deleted: bool,
}

impl Done<'_> {
    /// The rule's failure when the saved search is written (or retired) but
    /// an old one (*old*, when known) of the same rule could not be found or
    /// deleted: the next deploy finds it again. The old ones deleted before
    /// it (*warnings*) stay in the failure's `partial`, so the caller still
    /// lists them.
    fn cleanup_failed(
        &self,
        old: Option<&str>,
        error: &ConnectorError,
        operation: Operation,
        warnings: Vec<DeployWarning>,
    ) -> DeployError {
        let name = self.name;
        let done = if self.deleted {
            format!("saved search {name:?} was deleted (or already absent)")
        } else {
            format!("saved search {name:?} was written")
        };
        let deleted: Vec<String> = warnings
            .iter()
            .filter(|warning| warning.code == RENAMED_DELETED)
            .map(|warning| format!("{:?}", warning.message))
            .collect();
        let before = if deleted.is_empty() {
            String::new()
        } else {
            format!(" (deleted before it: {})", deleted.join(", "))
        };
        let message = match old {
            Some(old) => format!(
                "{done}, but {old:?}, a saved search an earlier name of this rule left, \
                 could not be deleted{before}: {}",
                error.text()
            ),
            None => format!(
                "{done}, but the saved searches an earlier name of this rule left could not \
                 be looked up: {}",
                error.text()
            ),
        };
        DeployError::rule(DeployFailure::new(RENAMED_CLEANUP_FAILED, message))
            .with_partial(DeployOutcome::new(None, operation).with_warnings(warnings))
    }
}

impl Deployer for Splunk {
    /// The tenant's address, app and token: nothing is sent.
    fn open<'a>(
        &'a self,
        cx: TenantContext<'a>,
    ) -> BoxFuture<'a, Result<(), crate::connector::DeployError>> {
        crate::connector::opening(async move {
            Self::authority(cx)?;
            Self::namespace(cx)?;
            cx.tenant.secret("token").map(|_| ())
        })
    }

    /// The saved search `rule_id` with the compiled settings in `body` (a
    /// JSON object: the rule's settings, its actions and `search`), through
    /// [`Splunk::apply_saved_search`]. A delete removes it when the tenant
    /// has it, with the warning `splunk_alert_deleted` (its message the
    /// name), and does nothing when it is already gone; its body may be
    /// `{"description": ..}`, the compiled description, to name the rule.
    ///
    /// When the body's `description` ends with the rule's marker
    /// ([`opentide_compile::splunk::described`]), the write or the delete is
    /// followed by one listing of the tenant app's saved searches and a
    /// delete of each other one owned by `nobody` that names the same rule:
    /// the ones an earlier name of the rule left, each said with the warning
    /// [`RENAMED_DELETED`] (its message the old name). A failed listing or
    /// delete fails the rule with [`RENAMED_CLEANUP_FAILED`]; the old ones
    /// deleted before it stay in the failure's `partial`.
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, crate::connector::DeployError>> {
        // Connector errors convert as `deploying` converts them; a rename's
        // cleanup fails the rule with its own code.
        Box::pin(self.deploy_saved_search(cx, request))
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
    fn a_name_is_one_form_encoded_segment() {
        assert_eq!(entity_name("Splunk SPL Rule"), "Splunk+SPL+Rule");
        assert_eq!(entity_name("a/b&c"), "a%2Fb%26c");
    }

    #[test]
    fn a_list_is_one_field_per_item() {
        let pairs = vec![
            ("search".to_owned(), Json::Str("index=* a&b".to_owned())),
            (
                "action".to_owned(),
                Json::Array(vec![Json::Str("x".to_owned()), Json::Bool(true)]),
            ),
        ];
        assert_eq!(form(&pairs), "search=index%3D*+a%26b&action=x&action=true");
    }

    #[test]
    fn queries_search_unless_they_start_with_a_command() {
        assert_eq!(spl_search(" index=main "), "search index=main");
        assert_eq!(spl_search("| tstats count"), "| tstats count");
        assert_eq!(spl_search("SEARCH x"), "SEARCH x");
    }

    #[test]
    fn atom_entries_read_as_the_python_client_reads_them() {
        let feed = br#"<feed xmlns="http://www.w3.org/2005/Atom" xmlns:s="http://dev.splunk.com/ns/rest"><entry><title>a b</title><link href="/servicesNS/nobody/search/saved/searches/a%20b" rel="alternate"/><content type="text/xml"><s:dict><s:key name="search">index=x &amp; y &lt;z&gt;</s:key></s:dict></content></entry></feed>"#;
        let found = entries(feed);
        assert_eq!(
            SavedSearch::from_entry(&found[0]),
            Some(SavedSearch {
                path: "saved/searches/a b".into(),
                search: Some("index=x & y <z>".into()),
            })
        );
        assert!(entries(b"not xml at all").is_empty());
    }

    #[test]
    fn an_error_body_gives_its_first_message_unescaped() {
        let message = |body: &str| match xml_message(body.as_bytes()) {
            XmlDetail::Message(text) => format!("message: {text}"),
            XmlDetail::None => "none".to_owned(),
            XmlDetail::NotXml => "not xml".to_owned(),
        };
        let wrapped = |inner: &str| {
            format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<response>{inner}</response>\n")
        };
        assert_eq!(
            message(&wrapped(
                "\n  <messages>\n    <msg type=\"FATAL\">Unknown &quot;x&quot; &amp; &#233;&#xe9; &lt;</msg>\n    <msg>second</msg>\n  </messages>\n"
            )),
            "message: Unknown \"x\" & éé <"
        );
        // No messages, a messages list that is empty, or one not first.
        assert_eq!(message(&wrapped("<other/>")), "none");
        assert_eq!(message(&wrapped("<messages/>")), "none");
        assert_eq!(
            message(&wrapped("<a/><messages><msg>late</msg></messages>")),
            "none"
        );
        // A page of HTML is no message; plain text is not XML. A body cut
        // off after a whole `msg` is no message either: the old regex read
        // one there, and the parser does not (Splunk sends whole documents).
        // One cut before a closing `>` is not XML, as before.
        assert_eq!(message("<html><body><br></body></html>"), "none");
        assert_eq!(message("<response><messages><msg>cut</msg>"), "none");
        assert_eq!(message("<response><messages><msg>cut"), "not xml");
        assert_eq!(message("Network Error"), "not xml");
        assert_eq!(message(""), "not xml");
    }

    #[test]
    fn a_feed_reads_its_links_and_keys_whatever_the_prefix() {
        let feed = br#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:s="http://dev.splunk.com/ns/rest" xmlns:opensearch="http://a9.com/-/spec/opensearch/1.1/">
  <entry>
    <link href="/services/server/info/server-info" rel="alternate"/>
    <link href="/services/server/info/server-info/other" rel="list"/>
    <content type="text/xml"><s:dict>
      <s:key name="instance_type">cloud</s:key>
      <s:key name="version">9.0.2209</s:key>
      <s:key name="version">ignored</s:key>
    </s:dict></content>
  </entry>
  <entry><title>second</title></entry>
</feed>"#;
        let found = entries(feed);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].key("instance_type").as_deref(), Some("cloud"));
        assert_eq!(found[0].key("version").as_deref(), Some("9.0.2209"));
        assert_eq!(found[0].key("absent"), None);
        assert_eq!(
            found[0].alternate.as_deref(),
            Some("/services/server/info/server-info")
        );
        assert_eq!(SavedSearch::from_entry(&found[1]), None);
    }

    #[test]
    fn every_quote_of_a_failed_answer_masks_the_token() {
        const TOKEN: &str = "splunk-token-never-shown";
        let mut request = crate::transport::Request::new(
            crate::transport::Method::POST,
            "https://splunk.invalid:8089/x".parse().unwrap(),
        );
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            format!("Bearer {TOKEN}").parse().unwrap(),
        );
        let credentials = crate::answer::Credentials::of(&request);
        let reply = |status, body: String| Reply {
            answer: Answer::new(
                status,
                None,
                body.into_bytes(),
                Duration::ZERO,
                &credentials,
            ),
        };
        let xml = format!(
            "<response><messages><msg type=\"ERROR\">bad {TOKEN}</msg></messages></response>"
        );
        let plain = format!("you sent Bearer {TOKEN}");
        let messages = format!(r#"{{"messages":[{{"type":"ERROR","text":"bad {TOKEN}"}}]}}"#);
        let mut shown = vec![
            reply(400, xml.clone()).http_error(),
            reply(400, xml).search_refusal(),
            reply(400, plain.clone()).search_refusal(),
            reply(200, plain.clone()).search_errors(&parse(plain.as_bytes())),
            reply(200, messages.clone()).search_errors(&parse(messages.as_bytes())),
        ];
        for (status, body) in [
            (503, plain.clone()),
            (400, plain),
            (401, messages.clone()),
            (400, messages),
        ] {
            let error = reply(status, body).check_failure("t").unwrap_err();
            shown.push(format!("{error} {}", error.text()));
        }
        for text in &shown {
            assert!(!text.contains(TOKEN), "{text}");
            assert!(text.contains("***"), "{text}");
        }
    }

    /// A parser check refused with HTTP 401 is the credential's, not the
    /// query's: the live check fails the tenant (#1658, E8).
    #[test]
    fn a_parser_check_refused_with_401_is_the_credentials() {
        let reply = |status, body: &[u8]| Reply {
            answer: Answer {
                status,
                content_type: None,
                body: body.to_vec(),
                elapsed: Duration::ZERO,
                credentials: crate::answer::Credentials::default(),
            },
        };
        let body = br#"{"messages":[{"type":"WARN","text":"call not properly authenticated"}]}"#;
        let error = reply(401, body).check_failure("lab").unwrap_err();
        let ConnectorError::Authentication { message, .. } = &error else {
            panic!("{error:?}")
        };
        assert_eq!(
            message,
            "Splunk refused the credential (HTTP 401): call not properly authenticated"
        );
        let error = reply(400, body).check_failure("lab").unwrap_err();
        assert!(matches!(error, ConnectorError::Refused { .. }), "{error:?}");
    }

    /// A saved search call refused with HTTP 401 refuses the token: the
    /// tenant's failure, so its other rules are not sent (#1701); any other
    /// refusal is the rule's.
    #[test]
    fn a_saved_search_call_refused_with_401_is_the_credentials() {
        let reply = |status, body: &[u8]| Reply {
            answer: Answer {
                status,
                content_type: None,
                body: body.to_vec(),
                elapsed: Duration::ZERO,
                credentials: crate::answer::Credentials::default(),
            },
        };
        let body = b"<response><messages><msg type=\"WARN\">call not properly authenticated</msg></messages></response>";
        let error = call_refusal("lab", &reply(401, body));
        let ConnectorError::Authentication { message, .. } = &error else {
            panic!("{error:?}")
        };
        assert_eq!(
            message,
            "Splunk answered HTTP 401 Unauthorized: call not properly authenticated"
        );
        let error = call_refusal("lab", &reply(400, body));
        assert!(matches!(error, ConnectorError::Refused { .. }), "{error:?}");
    }

    #[test]
    fn errors_quote_the_first_message_else_the_bytes() {
        let reply = |status, body: &[u8]| Reply {
            answer: Answer {
                status,
                content_type: None,
                body: body.to_vec(),
                elapsed: Duration::ZERO,
                credentials: crate::answer::Credentials::default(),
            },
        };
        assert_eq!(
            reply(404, b"").http_error(),
            "Splunk answered HTTP 404 Not Found"
        );
        assert_eq!(
            reply(
                400,
                b"<response><messages><msg type=\"ERROR\">Argument &quot;x&quot;</msg></messages></response>"
            )
            .http_error(),
            "Splunk answered HTTP 400 Bad Request: Argument \"x\""
        );
        assert_eq!(
            reply(400, b"{\"a\": 1}\n").http_error(),
            "Splunk answered HTTP 400 Bad Request: {\"a\": 1}"
        );
        assert_eq!(
            epoch("2026-10-27T08:00:00.25Z".parse().unwrap()),
            "1793088000.250"
        );
    }
}
