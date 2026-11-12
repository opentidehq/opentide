//! MISP's REST API, the subset `opentide share` speaks (UC-4.4b, #834;
//! `sharing/client.py`, which spoke it through PyMISP's `_prepare_request`).
//!
//! Every request carries the block's key in `Authorization`, asks for and
//! sends `application/json`, and has 30 seconds; TLS follows the block's
//! `verify_ssl`. A body is compact JSON in the order it was built (PyMISP's
//! `orjson.dumps`); a request without data sends no body. Answers are
//! classified as `_decode` does: never recorded, never echoed, a fixed
//! reason for every failure ([`MispCallError`]).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use opentide_compile::json::{Json, Object};
use tokio_util::sync::CancellationToken;

use crate::{Environment, HttpClient, HttpSettings, TenantLabel};

/// `REQUEST_TIMEOUT_SECONDS`.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// `SEARCH_PAGE_SIZE`.
pub const SEARCH_PAGE_SIZE: i64 = 100;
/// The pages a search reads at most (`_PAGE_CAP`).
const PAGE_CAP: i64 = 1000;
/// The `opentide` object template's UUID.
pub const OPENTIDE_TEMPLATE_UUID: &str = "892fd46a-f69e-455c-8c4f-843a4b8f4295";
/// The ATT&CK patterns' galaxy.
pub const GALAXY_ATTACK: &str = "mitre-attack-pattern";
/// The threat actors' galaxy.
pub const GALAXY_ACTOR: &str = "threat-actor";

/// What kind of failure a call met (`MispCallError.kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The key was refused (401, 403).
    Authentication,
    /// The instance could not be reached, or answered a 5xx or not JSON.
    Connectivity,
    /// The instance refused the request (another 4xx, `errors`).
    Rejected,
    /// An attribute was too long for the instance.
    AttributeTooLarge,
    /// Anything else (a 404, an organisation the instance does not name).
    Other,
}

impl Kind {
    /// The kind's name, as a record's `kind` holds it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Connectivity => "connectivity",
            Self::Rejected => "rejected",
            Self::AttributeTooLarge => "attribute_too_large",
            Self::Other => "other",
        }
    }
}

/// A destination failure: a fixed reason, never a body or a key
/// (`MispCallError`).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct MispCallError {
    /// What kind of failure.
    pub kind: Kind,
    /// The reason code (`connectivity_failed`, `not_found`, ...).
    pub reason: String,
    /// The HTTP status, when there was one.
    pub status: Option<u16>,
}

impl MispCallError {
    /// A failure of `kind` for `reason`.
    pub fn new(kind: Kind, reason: &str, status: Option<u16>) -> Self {
        Self {
            kind,
            reason: reason.to_owned(),
            status,
        }
    }
}

/// One MISP Event, from `events/view`, `events/add` or `events/edit`
/// (`RemoteEvent`).
#[derive(Clone, Debug, PartialEq)]
pub struct RemoteEvent {
    /// The instance's numeric id.
    pub event_id: Option<i64>,
    /// The event's UUID.
    pub event_uuid: String,
    /// The creating organisation's UUID.
    pub orgc_uuid: Option<String>,
    /// Whether it is published.
    pub published: bool,
    /// The `uuid` attributes of its objects.
    pub opentide_uuids: Vec<String>,
    /// How many attributes it holds outside objects.
    pub event_attribute_count: usize,
    /// Its objects, as the instance wrote them.
    pub objects: Vec<Object>,
}

impl RemoteEvent {
    /// The id the instance addresses it by: the number, else the UUID.
    pub fn address(&self) -> String {
        self.event_id
            .map_or_else(|| self.event_uuid.clone(), |id| id.to_string())
    }
}

/// The `opentide` object template as the instance reports it (`TemplateView`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TemplateView {
    /// Whether the instance has it.
    pub found: bool,
    /// Its version.
    pub version: Option<i64>,
    /// Its relations.
    pub relations: Vec<String>,
    /// The values `opentide-type` takes, when the template lists them.
    pub type_values: Option<Vec<String>>,
}

/// What `share` reads of one galaxy cluster (`GalaxyCluster`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GalaxyCluster {
    /// Its UUID.
    pub uuid: String,
    /// Its value (the tag's text).
    pub value: String,
    /// `meta.external_id`.
    pub external_ids: Vec<String>,
    /// `meta.synonyms`.
    pub synonyms: Vec<String>,
    /// The last path segment of each `meta.refs` URL.
    pub ref_tails: Vec<String>,
}

/// The calls `share` makes (`MispClient`); tests give a fake.
pub trait Misp: Sync {
    /// `servers/getVersion`.
    ///
    /// # Errors
    ///
    /// The call failed.
    fn get_version(&self) -> Result<String, MispCallError>;
    /// `users/view/me`: the key's organisation.
    ///
    /// # Errors
    ///
    /// The call failed, or the answer names no organisation.
    fn current_organisation_uuid(&self) -> Result<String, MispCallError>;
    /// The `opentide` object template.
    ///
    /// # Errors
    ///
    /// The call failed (a 404 is a template not found).
    fn object_template(&self) -> Result<TemplateView, MispCallError>;
    /// Every event holding an `opentide` object whose value is `object_uuid`.
    ///
    /// # Errors
    ///
    /// The call failed.
    fn search_opentide_events(&self, object_uuid: &str) -> Result<Vec<RemoteEvent>, MispCallError>;
    /// `events/add`.
    ///
    /// # Errors
    ///
    /// The call failed, or the answer is no event.
    fn add_event(&self, event: &Json) -> Result<RemoteEvent, MispCallError>;
    /// `events/edit/<id>`.
    ///
    /// # Errors
    ///
    /// The call failed, or the answer is no event.
    fn edit_event(&self, event_id: &str, event: &Json) -> Result<RemoteEvent, MispCallError>;
    /// `events/publish/<id>`.
    ///
    /// # Errors
    ///
    /// The call failed.
    fn publish_event(&self, event_id: &str) -> Result<(), MispCallError>;
    /// `events/unpublish/<id>`.
    ///
    /// # Errors
    ///
    /// The call failed.
    fn unpublish_event(&self, event_id: &str) -> Result<(), MispCallError>;
    /// `DELETE events/<id>`; an event already gone is deleted.
    ///
    /// # Errors
    ///
    /// The call failed.
    fn delete_event(&self, event_id: &str) -> Result<(), MispCallError>;
    /// Every cluster of `galaxy`, read once per client.
    ///
    /// # Errors
    ///
    /// The call failed.
    fn galaxy_clusters(&self, galaxy: &str) -> Result<Vec<GalaxyCluster>, MispCallError>;
}

/// The REST client of one `[[misp]]` block (`PyMispClient`).
pub struct MispClient {
    http: HttpClient,
    root: String,
    key: String,
    user_agent: String,
    runtime: tokio::runtime::Runtime,
    clusters: Mutex<HashMap<String, Vec<GalaxyCluster>>>,
}

impl std::fmt::Debug for MispClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MispClient")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl MispClient {
    /// The client of the instance at `url` (the block's `name` labels it),
    /// with `api_key`, through the proxy and CA bundles of `env` and
    /// `--proxy`; `version` is opentide's.
    ///
    /// # Errors
    ///
    /// The client cannot be built (a CA bundle that does not read, a proxy
    /// URL that does not parse): a connectivity failure.
    pub fn new(
        name: &str,
        url: &str,
        api_key: &str,
        verify_ssl: bool,
        env: &Environment,
        explicit_proxy: Option<&str>,
        version: &str,
    ) -> Result<Self, MispCallError> {
        let connectivity = || MispCallError::new(Kind::Connectivity, "connectivity_failed", None);
        let mut settings = HttpSettings {
            timeout: REQUEST_TIMEOUT,
            ..HttpSettings::default()
        };
        settings.tls.verify = verify_ssl;
        let http = HttpClient::new(
            &TenantLabel::new("misp", name),
            &settings,
            env,
            explicit_proxy,
        )
        .map_err(|_| connectivity())?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| connectivity())?;
        let root = if url.ends_with('/') {
            url.to_owned()
        } else {
            format!("{url}/")
        };
        Ok(Self {
            http,
            root,
            key: api_key.trim().to_owned(),
            user_agent: format!("opentide/{version}"),
            runtime,
            clusters: Mutex::new(HashMap::new()),
        })
    }

    /// One request; the decoded answer (`_request`, `_decode`).
    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        data: Option<&Json>,
    ) -> Result<Json, MispCallError> {
        let url = format!("{}{}", self.root, path.replace(' ', "+"));
        let connectivity = || MispCallError::new(Kind::Connectivity, "connectivity_failed", None);
        let mut builder = self
            .http
            .request(method, &url)
            .header(reqwest::header::AUTHORIZATION, &self.key)
            .header(reqwest::header::USER_AGENT, &self.user_agent)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        // PyMISP drops the top level's `None` values; an empty mapping is
        // no data at all (`dict(data) if data else None`).
        if let Some(Json::Object(object)) = data
            && !object.is_empty()
        {
            let kept: Object = object
                .iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            builder = builder.body(Json::Object(kept).to_compact());
        }
        let request = builder.build().map_err(|_| connectivity())?;
        let (status, body) = self
            .runtime
            .block_on(async {
                let cancel = CancellationToken::new();
                let response = self.http.send(request, &cancel).await.ok()?;
                let status = response.status().as_u16();
                let body = self.http.bytes(response, &cancel).await.ok()?;
                Some((status, body))
            })
            .ok_or_else(connectivity)?;
        decode(status, &body)
    }

    fn view(&self, remote: &RemoteEvent) -> Result<Option<RemoteEvent>, MispCallError> {
        match self.request(
            reqwest::Method::GET,
            &format!("events/view/{}", remote.address()),
            None,
        ) {
            Ok(payload) => Ok(remote_event(&payload)),
            Err(error) if error.status == Some(404) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn load_clusters(&self, galaxy: &str) -> Result<Vec<GalaxyCluster>, MispCallError> {
        let mut collected = Vec::new();
        let mut previous: Option<Vec<String>> = None;
        let mut page = 1;
        while page <= PAGE_CAP {
            let body = Json::Object(
                [
                    ("returnFormat", Json::Str("json".into())),
                    ("galaxy", Json::Str(galaxy.to_owned())),
                    ("page", Json::Int(page)),
                    ("limit", Json::Int(SEARCH_PAGE_SIZE)),
                ]
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
            );
            let payload = self.request(
                reqwest::Method::POST,
                "galaxy_clusters/restSearch",
                Some(&body),
            )?;
            let batch = event_nodes(&payload);
            let mut identities = Vec::new();
            for node in &batch {
                if let Some(found) = cluster(node, galaxy) {
                    identities.push(found.uuid.clone());
                    collected.push(found);
                }
            }
            if i64::try_from(batch.len()).unwrap_or(i64::MAX) < SEARCH_PAGE_SIZE
                || previous.as_ref() == Some(&identities)
            {
                break;
            }
            previous = Some(identities);
            page += 1;
        }
        Ok(collected)
    }
}

impl Misp for MispClient {
    fn get_version(&self) -> Result<String, MispCallError> {
        let payload = self.request(reqwest::Method::GET, "servers/getVersion", None)?;
        match payload.get("version") {
            Some(Json::Str(version)) if !version.is_empty() => Ok(version.clone()),
            _ => Err(MispCallError::new(
                Kind::Connectivity,
                "connectivity_failed",
                None,
            )),
        }
    }

    fn current_organisation_uuid(&self) -> Result<String, MispCallError> {
        let payload = self.request(reqwest::Method::GET, "users/view/me", None)?;
        organisation_uuid(&payload)
            .ok_or_else(|| MispCallError::new(Kind::Other, "organisation_uuid_unverified", None))
    }

    fn object_template(&self) -> Result<TemplateView, MispCallError> {
        match self.request(
            reqwest::Method::GET,
            &format!("objectTemplates/view/{OPENTIDE_TEMPLATE_UUID}"),
            None,
        ) {
            Ok(payload) => Ok(template_view(&payload)),
            Err(error) if error.status == Some(404) => Ok(TemplateView::default()),
            Err(error) => Err(error),
        }
    }

    fn search_opentide_events(&self, object_uuid: &str) -> Result<Vec<RemoteEvent>, MispCallError> {
        let mut found = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        let mut previous: Option<Vec<String>> = None;
        let mut page = 1;
        while page <= PAGE_CAP {
            let body = Json::Object(
                [
                    ("returnFormat", Json::Str("json".into())),
                    ("object_name", Json::Str("opentide".into())),
                    ("value", Json::Str(object_uuid.to_owned())),
                    ("page", Json::Int(page)),
                    ("limit", Json::Int(SEARCH_PAGE_SIZE)),
                ]
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
            );
            let payload = self.request(reqwest::Method::POST, "events/restSearch", Some(&body))?;
            let batch = event_nodes(&payload);
            let mut identities = Vec::new();
            for node in &batch {
                let Some(remote) = remote_event(node) else {
                    continue;
                };
                identities.push(remote.event_uuid.clone());
                if seen.contains(&remote.event_uuid) {
                    continue;
                }
                seen.push(remote.event_uuid.clone());
                if let Some(full) = self.view(&remote)? {
                    found.push(full);
                }
            }
            if i64::try_from(batch.len()).unwrap_or(i64::MAX) < SEARCH_PAGE_SIZE
                || previous.as_ref() == Some(&identities)
            {
                break;
            }
            previous = Some(identities);
            page += 1;
        }
        Ok(found)
    }

    fn add_event(&self, event: &Json) -> Result<RemoteEvent, MispCallError> {
        let payload = self.request(reqwest::Method::POST, "events/add", Some(event))?;
        remote_event(&payload)
            .ok_or_else(|| MispCallError::new(Kind::Rejected, "remote_rejected", None))
    }

    fn edit_event(&self, event_id: &str, event: &Json) -> Result<RemoteEvent, MispCallError> {
        let payload = self.request(
            reqwest::Method::POST,
            &format!("events/edit/{event_id}"),
            Some(event),
        )?;
        remote_event(&payload)
            .ok_or_else(|| MispCallError::new(Kind::Rejected, "remote_update_rejected", None))
    }

    fn publish_event(&self, event_id: &str) -> Result<(), MispCallError> {
        self.request(
            reqwest::Method::POST,
            &format!("events/publish/{event_id}"),
            None,
        )
        .map(|_| ())
    }

    fn unpublish_event(&self, event_id: &str) -> Result<(), MispCallError> {
        self.request(
            reqwest::Method::POST,
            &format!("events/unpublish/{event_id}"),
            None,
        )
        .map(|_| ())
    }

    fn delete_event(&self, event_id: &str) -> Result<(), MispCallError> {
        match self.request(reqwest::Method::DELETE, &format!("events/{event_id}"), None) {
            Ok(_) => Ok(()),
            Err(error) if error.status == Some(404) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn galaxy_clusters(&self, galaxy: &str) -> Result<Vec<GalaxyCluster>, MispCallError> {
        if let Ok(cache) = self.clusters.lock()
            && let Some(known) = cache.get(galaxy)
        {
            return Ok(known.clone());
        }
        let loaded = self.load_clusters(galaxy)?;
        if let Ok(mut cache) = self.clusters.lock() {
            cache.insert(galaxy.to_owned(), loaded.clone());
        }
        Ok(loaded)
    }
}

/// An answer classified as `_decode` classifies it.
///
/// # Errors
///
/// An error status, a body that is not JSON, or an `errors` member.
pub fn decode(status: u16, body: &[u8]) -> Result<Json, MispCallError> {
    if status == 401 || status == 403 {
        return Err(MispCallError::new(
            Kind::Authentication,
            "authentication_failed",
            Some(status),
        ));
    }
    if status == 404 {
        return Err(MispCallError::new(Kind::Other, "not_found", Some(404)));
    }
    if status >= 500 {
        return Err(MispCallError::new(
            Kind::Connectivity,
            "connectivity_failed",
            Some(status),
        ));
    }
    let text = String::from_utf8_lossy(body);
    if status >= 400 {
        if too_large(&text) {
            return Err(MispCallError::new(
                Kind::AttributeTooLarge,
                "attribute_too_large",
                Some(status),
            ));
        }
        return Err(MispCallError::new(
            Kind::Rejected,
            "remote_rejected",
            Some(status),
        ));
    }
    if text.trim().is_empty() {
        return Ok(Json::Object(Object::new()));
    }
    let payload: Json = serde_json::from_str(&text)
        .map_err(|_| MispCallError::new(Kind::Connectivity, "connectivity_failed", None))?;
    if let Json::Object(object) = &payload
        && let Some(errors) = object.get("errors")
    {
        if too_large(&python_dumps(errors)) {
            return Err(MispCallError::new(
                Kind::AttributeTooLarge,
                "attribute_too_large",
                None,
            ));
        }
        let code = match errors {
            Json::Array(items) => match items.first() {
                Some(Json::Int(code)) => u16::try_from(*code).ok(),
                _ => None,
            },
            _ => None,
        };
        if code == Some(401) || code == Some(403) {
            return Err(MispCallError::new(
                Kind::Authentication,
                "authentication_failed",
                code,
            ));
        }
        return Err(MispCallError::new(Kind::Rejected, "remote_rejected", code));
    }
    if let Some(response @ (Json::Object(_) | Json::Array(_))) = payload.get("response") {
        return Ok(response.clone());
    }
    Ok(payload)
}

/// `json.dumps` of a value, enough to look for words in it.
fn python_dumps(value: &Json) -> String {
    value.to_compact()
}

/// Whether an error text says an attribute was too long (`_too_large`).
fn too_large(text: &str) -> bool {
    let folded = text.to_lowercase();
    folded.contains("too long") || folded.contains("too large") || folded.contains("maximum length")
}

fn organisation_uuid(payload: &Json) -> Option<String> {
    if let Some(Json::Str(uuid)) = payload.get("Organisation").and_then(|org| org.get("uuid")) {
        return Some(uuid.clone());
    }
    match payload
        .get("User")
        .and_then(|user| user.get("Organisation"))
        .and_then(|org| org.get("uuid"))
    {
        Some(Json::Str(uuid)) => Some(uuid.clone()),
        _ => None,
    }
}

/// The event nodes of a search answer (`_event_nodes`).
fn event_nodes(payload: &Json) -> Vec<Json> {
    match payload {
        Json::Array(items) => items.clone(),
        Json::Object(object) => {
            if matches!(object.get("Event"), Some(Json::Object(_))) {
                return vec![payload.clone()];
            }
            let response = object.get("response").unwrap_or(payload);
            match response {
                Json::Array(items) => items.clone(),
                Json::Object(inner) => {
                    if matches!(inner.get("Event"), Some(Json::Object(_))) {
                        return vec![response.clone()];
                    }
                    inner
                        .values()
                        .filter(|value| matches!(value, Json::Object(_)))
                        .cloned()
                        .collect()
                }
                _ => Vec::new(),
            }
        }
        _ => Vec::new(),
    }
}

/// An event from an answer (`_remote_event`).
pub fn remote_event(payload: &Json) -> Option<RemoteEvent> {
    let Json::Object(outer) = payload else {
        return None;
    };
    let event = outer.get("Event").unwrap_or(payload);
    let Json::Object(event) = event else {
        return None;
    };
    let event_uuid = match event.get("uuid") {
        Some(Json::Str(uuid)) if !uuid.is_empty() => uuid.clone(),
        _ => return None,
    };
    let orgc_uuid = match event.get("Orgc").and_then(|orgc| orgc.get("uuid")) {
        Some(Json::Str(uuid)) => Some(uuid.clone()),
        _ => None,
    };
    let objects = object_dicts(event.get("Object"));
    Some(RemoteEvent {
        event_id: integer(event.get("id")),
        event_uuid,
        orgc_uuid,
        published: flag(event.get("published")),
        opentide_uuids: opentide_uuids(&objects),
        event_attribute_count: match event.get("Attribute") {
            Some(Json::Array(items)) => items.len(),
            _ => 0,
        },
        objects,
    })
}

fn opentide_uuids(objects: &[Object]) -> Vec<String> {
    let mut found = Vec::new();
    for object in objects {
        let Some(Json::Array(attributes)) = object.get("Attribute") else {
            continue;
        };
        for attribute in attributes {
            if attribute.get("object_relation").and_then(Json::as_str) == Some("uuid")
                && let Some(Json::Str(value)) = attribute.get("value")
            {
                found.push(value.clone());
            }
        }
    }
    found
}

fn object_dicts(objects: Option<&Json>) -> Vec<Object> {
    match objects {
        Some(Json::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_object().cloned())
            .collect(),
        _ => Vec::new(),
    }
}

fn template_view(payload: &Json) -> TemplateView {
    let Json::Object(outer) = payload else {
        return TemplateView::default();
    };
    let root = outer.get("ObjectTemplate").unwrap_or(payload);
    let Json::Object(root) = root else {
        return TemplateView::default();
    };
    let elements = match root.get("ObjectTemplateElement") {
        Some(Json::Array(items)) => Some(items),
        _ => match root.get("attributes") {
            Some(Json::Array(items)) => Some(items),
            _ => None,
        },
    };
    let mut relations: Vec<String> = Vec::new();
    let mut type_values = None;
    for element in elements.into_iter().flatten() {
        let Json::Object(element) = element else {
            continue;
        };
        let relation = element.get("object_relation").and_then(Json::as_str);
        if let Some(relation) = relation
            && !relations.iter().any(|seen| seen == relation)
        {
            relations.push(relation.to_owned());
        }
        if relation == Some("opentide-type") {
            type_values = values_list(element.get("values_list"));
        }
    }
    TemplateView {
        found: true,
        version: integer(root.get("version")),
        relations,
        type_values,
    }
}

fn values_list(value: Option<&Json>) -> Option<Vec<String>> {
    let strings = |items: &[Json]| {
        items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect()
    };
    match value {
        Some(Json::Array(items)) => Some(strings(items)),
        Some(Json::Str(text)) if !text.trim().is_empty() => {
            match serde_json::from_str::<Json>(text) {
                Ok(Json::Array(items)) => Some(strings(&items)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn cluster(node: &Json, galaxy: &str) -> Option<GalaxyCluster> {
    let Json::Object(outer) = node else {
        return None;
    };
    let raw = outer.get("GalaxyCluster").unwrap_or(node);
    let Json::Object(raw) = raw else {
        return None;
    };
    let galaxy_node = match outer.get("Galaxy") {
        Some(found @ Json::Object(_)) => Some(found),
        _ => raw
            .get("Galaxy")
            .filter(|found| found.as_object().is_some()),
    };
    if let Some(galaxy_node) = galaxy_node {
        let kind = galaxy_node
            .get("type")
            .filter(|kind| kind.truthy())
            .or_else(|| galaxy_node.get("name"));
        if let Some(Json::Str(kind)) = kind
            && kind != galaxy
        {
            return None;
        }
    }
    let (Some(Json::Str(uuid)), Some(Json::Str(value))) = (raw.get("uuid"), raw.get("value"))
    else {
        return None;
    };
    let meta = raw
        .get("meta")
        .filter(|meta| meta.truthy())
        .or_else(|| raw.get("meta_fields").filter(|meta| meta.truthy()));
    let meta = match meta {
        Some(Json::Str(text)) => serde_json::from_str::<Json>(text).ok(),
        other => other.cloned(),
    };
    let meta = match meta {
        Some(Json::Object(meta)) => meta,
        _ => Object::new(),
    };
    Some(GalaxyCluster {
        uuid: uuid.clone(),
        value: value.clone(),
        external_ids: strings(meta.get("external_id")),
        synonyms: strings(meta.get("synonyms")),
        ref_tails: strings(meta.get("refs"))
            .iter()
            .map(|reference| ref_tail(reference))
            .collect(),
    })
}

fn strings(value: Option<&Json>) -> Vec<String> {
    match value {
        Some(Json::Str(text)) => vec![text.clone()],
        Some(Json::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The last segment of a URL's path (`_ref_tail`).
fn ref_tail(reference: &str) -> String {
    let path = match url::Url::parse(reference) {
        Ok(parsed) => parsed.path().to_owned(),
        Err(_) => reference
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    };
    let path = path.trim_end_matches('/');
    path.rsplit('/').next().unwrap_or_default().to_owned()
}

fn integer(value: Option<&Json>) -> Option<i64> {
    match value {
        Some(Json::Int(number)) => Some(*number),
        Some(Json::Str(text)) if !text.is_empty() && text.chars().all(|c| c.is_ascii_digit()) => {
            text.parse().ok()
        }
        _ => None,
    }
}

fn flag(value: Option<&Json>) -> bool {
    match value {
        Some(Json::Str(text)) => text == "1" || text.to_lowercase() == "true",
        Some(other) => other.truthy(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> Json {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn decode_classifies_statuses_and_bodies() {
        let kind = |status: u16, body: &str| decode(status, body.as_bytes()).unwrap_err();
        assert_eq!(kind(401, "").kind, Kind::Authentication);
        assert_eq!(kind(403, "").reason, "authentication_failed");
        assert_eq!(kind(404, "").status, Some(404));
        assert_eq!(kind(502, "<html>").kind, Kind::Connectivity);
        assert_eq!(kind(400, "Value Too Long").kind, Kind::AttributeTooLarge);
        assert_eq!(kind(422, "nope").reason, "remote_rejected");
        assert_eq!(kind(200, "<html>").reason, "connectivity_failed");
        assert_eq!(
            kind(200, r#"{"errors": [403, {"message": "x"}]}"#).kind,
            Kind::Authentication
        );
        assert_eq!(
            kind(200, r#"{"errors": {"value": "maximum length exceeded"}}"#).kind,
            Kind::AttributeTooLarge
        );
        assert_eq!(
            kind(200, r#"{"errors": [400]}"#).status,
            Some(400),
            "the status the errors name"
        );
        assert_eq!(decode(200, b"  ").unwrap(), Json::Object(Object::new()));
        assert_eq!(
            decode(200, br#"{"response": [1]}"#).unwrap(),
            json("[1]"),
            "a response member is the answer"
        );
        assert_eq!(
            decode(200, br#"{"response": "x"}"#).unwrap(),
            json(r#"{"response": "x"}"#)
        );
    }

    #[test]
    fn events_are_read_from_every_shape() {
        let event = json(
            r#"{"Event": {"id": "12", "uuid": "e1", "Orgc": {"uuid": "o1"}, "published": "1",
                "Attribute": [{}], "Object": [{"name": "opentide", "Attribute": [
                {"object_relation": "uuid", "value": "t1"}, {"object_relation": "name", "value": "n"}]},
                "not an object"]}}"#,
        );
        let remote = remote_event(&event).unwrap();
        assert_eq!(remote.event_id, Some(12));
        assert_eq!(remote.address(), "12");
        assert_eq!(remote.orgc_uuid.as_deref(), Some("o1"));
        assert!(remote.published);
        assert_eq!(remote.opentide_uuids, ["t1"]);
        assert_eq!(remote.event_attribute_count, 1);
        assert_eq!(remote.objects.len(), 1);
        let bare =
            remote_event(&json(r#"{"uuid": "e2", "published": false, "id": true}"#)).unwrap();
        assert_eq!(bare.address(), "e2");
        assert!(!bare.published);
        assert!(remote_event(&json(r#"{"uuid": ""}"#)).is_none());
        assert!(remote_event(&json("[]")).is_none());
        assert!(remote_event(&json(r#"{"Event": []}"#)).is_none());

        assert_eq!(event_nodes(&json("[1, 2]")).len(), 2);
        assert_eq!(event_nodes(&event).len(), 1);
        assert_eq!(
            event_nodes(&json(r#"{"response": {"Event": {"uuid": "x"}}}"#)).len(),
            1
        );
        assert_eq!(event_nodes(&json(r#"{"a": {"x": 1}, "b": 2}"#)).len(), 1);
        assert!(event_nodes(&json(r#""x""#)).is_empty());
        assert!(event_nodes(&json(r#"{"response": 3}"#)).is_empty());
    }

    #[test]
    fn organisations_templates_and_clusters_are_read() {
        assert_eq!(
            organisation_uuid(&json(r#"{"Organisation": {"uuid": "a"}}"#)).as_deref(),
            Some("a")
        );
        assert_eq!(
            organisation_uuid(&json(r#"{"User": {"Organisation": {"uuid": "b"}}}"#)).as_deref(),
            Some("b")
        );
        assert_eq!(organisation_uuid(&json("{}")), None);

        let view = template_view(&json(
            r#"{"ObjectTemplate": {"version": "5", "ObjectTemplateElement": [
                {"object_relation": "uuid"}, {"object_relation": "opentide-type",
                "values_list": "[\"rule\", \"threat\"]"}, 3]}}"#,
        ));
        assert!(view.found);
        assert_eq!(view.version, Some(5));
        assert_eq!(view.relations, ["uuid", "opentide-type"]);
        assert_eq!(view.type_values, Some(vec!["rule".into(), "threat".into()]));
        let listed = template_view(&json(
            r#"{"attributes": [{"object_relation": "opentide-type", "values_list": ["x"]}]}"#,
        ));
        assert_eq!(listed.type_values, Some(vec!["x".into()]));
        assert!(!template_view(&json("[]")).found);
        assert_eq!(values_list(Some(&json(r#""nope""#))), None);

        let node = json(
            r#"{"GalaxyCluster": {"uuid": "u", "value": "APT", "meta": "{\"synonyms\": [\"x\"], \"external_id\": \"G1\", \"refs\": [\"https://attack.mitre.org/groups/G0001/\"]}"},
                "Galaxy": {"type": "threat-actor"}}"#,
        );
        let found = cluster(&node, GALAXY_ACTOR).unwrap();
        assert_eq!(found.external_ids, ["G1"]);
        assert_eq!(found.synonyms, ["x"]);
        assert_eq!(found.ref_tails, ["G0001"]);
        assert!(cluster(&node, GALAXY_ATTACK).is_none());
        assert!(cluster(&json(r#"{"uuid": "u"}"#), GALAXY_ATTACK).is_none());
        assert_eq!(ref_tail("not a url/a/b"), "b");
    }

    #[test]
    fn flags_and_integers_follow_python() {
        assert!(flag(Some(&json(r#""True""#))));
        assert!(!flag(Some(&json(r#""0""#))));
        assert!(flag(Some(&json("1"))));
        assert!(!flag(None));
        assert_eq!(integer(Some(&json(r#""42""#))), Some(42));
        assert_eq!(integer(Some(&json(r#""-1""#))), None);
        assert_eq!(integer(Some(&json("true"))), None);
    }
}
