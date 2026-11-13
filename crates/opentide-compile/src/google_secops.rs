//! Google Security Operations (google-secops-1.0), ported from 0.28.0's
//! `platforms/google_secops/compile.py`: the YARA-L text a rule deploys
//! (`opentide-schema`'s assembled rule, fed with the facts it derives from
//! the rule), the run state a status strategy deploys (`run_state`,
//! `RunState.changes`), and the Chronicle API's resource names and request
//! bodies the connector sends.
//!
//! The text is the same on every tenant: `compile_offline` is the
//! `rules.create` body (`{"text": ...}`), as 0.28.0's preview shows it.

use opentide_schema::node::{Entry, Mark, Node, Value};
use opentide_schema::objects::platform::google_secops::assemble::{
    self as assembly, AssembledRule, RuleFacts,
};
use opentide_schema::objects::platform::google_secops::duration_seconds;

use crate::deploy::{self, Write};
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;
use crate::{Context, elastic};

/// The platform's key under `configurations`.
pub const PLATFORM: &str = "google_secops";

/// The platform's display name, in a failure's message.
pub const DISPLAY: &str = "Google SecOps";

/// A YAML node of a JSON value, keys in order and without positions: the
/// form `opentide-schema`'s assembly reads.
pub fn node_of(value: &Json) -> Node {
    let value = match value {
        Json::Null => Value::Null,
        Json::Bool(flag) => Value::Bool(*flag),
        Json::Int(integer) => Value::Int(*integer),
        Json::Float(float) => Value::Float(*float),
        Json::Str(text) => Value::Str(text.clone()),
        Json::Array(items) => Value::Seq(items.iter().map(|item| node_of(item).into()).collect()),
        Json::Object(map) => Value::Map(
            map.iter()
                .map(|(key, item)| Entry {
                    key: Node {
                        value: Value::Str(key.clone()),
                        start: Mark::default(),
                        end: Mark::default(),
                    }
                    .into(),
                    value: node_of(item).into(),
                })
                .collect(),
        ),
    };
    Node {
        value,
        start: Mark::default(),
        end: Mark::default(),
    }
}

/// What the derived `meta` reads off `rule`: its title, uuid, version,
/// author, description, `response.alert_severity` when set, and its
/// techniques with those it inherits through `detection_model`, sorted.
pub fn facts(cx: &Context<'_>, rule: &Rule) -> RuleFacts {
    let metadata = rule.data.get("metadata");
    let field = |key: &str| {
        metadata
            .and_then(|metadata| metadata.get(key))
            .filter(|value| !value.is_null())
            .map(deploy::text)
    };
    let mut techniques = elastic::rule_techniques(cx, rule);
    techniques.sort();
    techniques.dedup();
    RuleFacts {
        title: rule.name.clone(),
        uuid: rule.uuid.clone(),
        version: field("version").unwrap_or_else(|| "None".to_owned()),
        author: field("author"),
        description: rule.description().to_owned(),
        alert_severity: rule
            .response()
            .and_then(|response| response.get("alert_severity"))
            .filter(|value| !value.is_null())
            .map(deploy::text),
        techniques,
    }
}

/// The rule's block as a node, or the failure of a rule without one.
pub fn block_node(rule: &Rule) -> Result<Node, CompileError> {
    rule.block(PLATFORM).map(node_of).ok_or_else(|| {
        CompileError::failed(
            DISPLAY,
            &format!(
                "rule {} has no google_secops block",
                opentide_schema::configuration::repr::quote(&rule.name)
            ),
        )
    })
}

/// The YARA-L rule `rule` deploys (`assemble`).
pub fn assemble(cx: &Context<'_>, rule: &Rule) -> Result<AssembledRule, CompileError> {
    let block = block_node(rule)?;
    assembly::assemble(&facts(cx, rule), &block)
        .map_err(|error| CompileError::failed(DISPLAY, &error.to_string()))
}

/// The `rules.create` body a deploy would send for `rule`, without a
/// tenant's scope (`compile_offline`).
pub fn compile_offline(cx: &Context<'_>, rule: &Rule) -> Result<Json, CompileError> {
    let assembled = assemble(cx, rule)?;
    let mut body = Object::new();
    body.insert("text".into(), Json::Str(assembled.text));
    Ok(Json::Object(body))
}

// --- run state -------------------------------------------------------------

/// `scheduleCustomizations` for the block's `schedule`, or `None`.
pub fn schedule_customizations(block: &Json) -> Option<Json> {
    let schedule = block.get("schedule").filter(|value| !value.is_null())?;
    let mut custom = Object::new();
    if let Some(Json::Bool(flag)) = schedule.get("ensure_enrichment_completeness") {
        custom.insert("ensureEnrichmentCompleteness".into(), Json::Bool(*flag));
    }
    if let Some(seconds) = schedule
        .get("late_arriving_data_adjustment")
        .and_then(Json::as_str)
        .and_then(duration_seconds)
    {
        custom.insert(
            "lateArrivingDataAdjustment".into(),
            Json::Str(format!("{seconds}s")),
        );
    }
    Some(Json::Object(custom))
}

/// A protobuf `Duration` in JSON (`"1800s"`, `"1800.000s"`) in seconds, or
/// `None`.
pub fn protobuf_seconds(value: Option<&Json>) -> Option<f64> {
    let text = value?.as_str()?.trim();
    let number = text.strip_suffix('s')?;
    let (whole, fraction) = number.split_once('.').unwrap_or((number, "0"));
    if whole.is_empty()
        || !whole.chars().all(|ch| ch.is_ascii_digit())
        || fraction.is_empty()
        || !fraction.chars().all(|ch| ch.is_ascii_digit())
    {
        return None;
    }
    number.parse().ok()
}

/// A `scheduleCustomizations` as Google stores it: an absent boolean is
/// `false`, an absent or zero adjustment `0`.
fn settled_schedule(custom: Option<&Json>) -> (bool, f64) {
    let Some(Json::Object(custom)) = custom else {
        return (false, 0.0);
    };
    (
        custom
            .get("ensureEnrichmentCompleteness")
            .is_some_and(Json::truthy),
        protobuf_seconds(custom.get("lateArrivingDataAdjustment")).unwrap_or(0.0),
    )
}

/// `RuleDeployment` fields deploy sets, in `updateMask` order.
const RUN_STATE_FIELDS: [&str; 3] = ["enabled", "alerting", "runFrequency"];

/// A `RuleDeployment` update: its `updateMask` and body.
#[derive(Debug, Clone, PartialEq)]
pub struct RunState {
    /// The `updateMask`.
    pub mask: String,
    /// The body.
    pub body: Object,
}

impl RunState {
    /// The disabled state: `enabled` and `alerting` off.
    pub fn disabled() -> Self {
        let mut body = Object::new();
        body.insert("enabled".into(), Json::Bool(false));
        body.insert("alerting".into(), Json::Bool(false));
        Self {
            mask: "enabled,alerting".to_owned(),
            body,
        }
    }

    /// The part of this update `remote` (a `RuleDeployment`) does not hold
    /// yet, or `None`.
    ///
    /// Google leaves a false boolean out of its answer. `runFrequency`
    /// carries `scheduleCustomizations`: the schedule is compared as Google
    /// stores it, and a block with no `schedule` wants none, so one left on
    /// the remote rule is cleared by sending `runFrequency` alone.
    pub fn changes(&self, remote: &Json) -> Option<Self> {
        let mut changed: Vec<&str> = Vec::new();
        for key in RUN_STATE_FIELDS {
            let Some(value) = self.body.get(key) else {
                continue;
            };
            if key == "runFrequency" {
                let wanted = settled_schedule(self.body.get("scheduleCustomizations"));
                let current = settled_schedule(remote.get("scheduleCustomizations"));
                if remote.get(key) != Some(value) || wanted != current {
                    changed.push(key);
                }
            } else if remote.get(key).is_some_and(Json::truthy) != value.truthy() {
                changed.push(key);
            }
        }
        if changed.is_empty() {
            return None;
        }
        let mut body = Object::new();
        for key in &changed {
            if let Some(value) = self.body.get(*key) {
                body.insert((*key).to_owned(), value.clone());
            }
        }
        if changed.contains(&"runFrequency")
            && let Some(custom) = self.body.get("scheduleCustomizations")
        {
            body.insert("scheduleCustomizations".into(), custom.clone());
        }
        Some(Self {
            mask: changed.join(","),
            body,
        })
    }

    /// Whether `remote` holds another value for a field this update sends.
    pub fn differs_from(&self, remote: &Json) -> bool {
        self.changes(remote).is_some()
    }
}

/// The deployment update for `strategy` (google-secops-1.0, Run state by
/// strategy).
///
/// `runFrequency` is sent only when the block names one: without it Google
/// keeps the rule's frequency, or gives a new rule its default, and never
/// moves a legacy schedule, which Google cannot move back.
pub fn run_state(block: &Json, strategy: StatusStrategy) -> RunState {
    if matches!(
        strategy,
        StatusStrategy::Disablement | StatusStrategy::Deletion
    ) {
        return RunState::disabled();
    }
    let alerting = match block.get("alerting") {
        Some(Json::Bool(flag)) => *flag,
        _ => strategy != StatusStrategy::Preview,
    };
    let mut body = Object::new();
    body.insert("enabled".into(), Json::Bool(true));
    body.insert("alerting".into(), Json::Bool(alerting));
    let Some(frequency) = block.get("run_frequency").filter(|value| !value.is_null()) else {
        return RunState {
            mask: "enabled,alerting".to_owned(),
            body,
        };
    };
    body.insert("runFrequency".into(), frequency.clone());
    if let Some(custom) = schedule_customizations(block) {
        body.insert("scheduleCustomizations".into(), custom);
    }
    RunState {
        mask: "enabled,alerting,runFrequency".to_owned(),
        body,
    }
}

// --- resources and requests ------------------------------------------------

/// `projects/{project}/locations/{location}/instances/{instance}`.
pub fn instance_resource(project: &str, location: &str, instance: &str) -> String {
    format!("projects/{project}/locations/{location}/instances/{instance}")
}

/// The Chronicle API's regional endpoint.
pub fn default_endpoint(location: &str) -> String {
    format!("https://{location}-chronicle.googleapis.com")
}

/// The tenant's endpoint: `setup.endpoint`, else the regional one.
pub fn endpoint(tenant: &Json) -> String {
    let endpoint = deploy::setup_text(tenant, "endpoint");
    if endpoint.is_empty() {
        default_endpoint(&deploy::setup_text(tenant, "location"))
    } else {
        endpoint
    }
}

/// The tenant's instance resource.
pub fn tenant_instance(tenant: &Json) -> String {
    instance_resource(
        &deploy::setup_text(tenant, "project"),
        &deploy::setup_text(tenant, "location"),
        &deploy::setup_text(tenant, "instance"),
    )
}

/// The `scope` for a tenant's `data_access_scope`: a full resource name
/// (`projects/…/dataAccessScopes/<id>`) is used as given; an id becomes
/// `<instance>/dataAccessScopes/<id>`.
pub fn scope_resource(instance: &str, scope: Option<&str>) -> Option<String> {
    let scope = scope?.trim().trim_matches('/');
    if scope.is_empty() {
        return None;
    }
    if format!("/{scope}").contains("/dataAccessScopes/") {
        Some(scope.to_owned())
    } else {
        Some(format!("{instance}/dataAccessScopes/{scope}"))
    }
}

/// The data access scope id of a scope resource name, `""` for none.
pub fn scope_id(scope: &str) -> &str {
    scope
        .rsplit_once("/dataAccessScopes/")
        .map_or(scope, |(_, id)| id)
}

/// A rule id as a path segment: percent-encoded, nothing kept (Python's
/// `quote(rule_id, safe='')`).
pub fn rule_path(rule_id: &str) -> String {
    let mut out = String::from("rules/");
    for byte in rule_id.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// One request: method, path from the API root (`/v1/<instance>…`), query
/// and body, as the fixtures record it.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// `GET`, `POST`, `PATCH` or `DELETE`.
    pub method: &'static str,
    /// `/v1/projects/…/instances/…:verifyRuleText`, `/v1/…/rules`.
    pub path: String,
    /// The query parameters, in order.
    pub query: Vec<(&'static str, String)>,
    /// The JSON body, when there is one.
    pub body: Option<Json>,
}

impl Request {
    fn new(method: &'static str, instance: &str, path: &str, body: Option<Json>) -> Self {
        let path = if path.starts_with(':') {
            format!("/v1/{instance}{path}")
        } else {
            format!("/v1/{instance}/{path}")
        };
        Self {
            method,
            path,
            query: Vec::new(),
            body,
        }
    }

    fn with_query(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.query.push((key, value.into()));
        self
    }

    /// `{"method", "path", "query"?, "body"?}`, as the `.api.json` fixtures
    /// hold a request.
    pub fn to_json(&self) -> Json {
        let mut object = Object::new();
        object.insert("method".into(), self.method.into());
        object.insert("path".into(), self.path.clone().into());
        if !self.query.is_empty() {
            let mut query = Object::new();
            for (key, value) in &self.query {
                query.insert((*key).to_owned(), value.clone().into());
            }
            object.insert("query".into(), Json::Object(query));
        }
        if let Some(body) = &self.body {
            object.insert("body".into(), body.clone());
        }
        Json::Object(object)
    }

    /// The write a dry run shows: the full URL and the body.
    pub fn to_write(&self, endpoint: &str) -> Write {
        let mut url = format!("{}{}", endpoint.trim_end_matches('/'), self.path);
        if !self.query.is_empty() {
            let query: Vec<String> = self
                .query
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect();
            url.push('?');
            url.push_str(&query.join("&"));
        }
        Write::new(self.method, url, self.body.clone().unwrap_or(Json::Null))
    }
}

fn object(entries: &[(&str, Json)]) -> Json {
    let mut out = Object::new();
    for (key, value) in entries {
        out.insert((*key).to_owned(), value.clone());
    }
    Json::Object(out)
}

/// `POST :verifyRuleText`.
pub fn verify_request(instance: &str, text: &str) -> Request {
    Request::new(
        "POST",
        instance,
        ":verifyRuleText",
        Some(object(&[("ruleText", text.into())])),
    )
}

/// `POST rules`, with the tenant's scope when it names one.
pub fn create_request(instance: &str, text: &str, scope: Option<&str>) -> Request {
    let mut body = vec![("text", Json::from(text))];
    if let Some(scope) = scope.filter(|scope| !scope.is_empty()) {
        body.push(("scope", scope.into()));
    }
    Request::new("POST", instance, "rules", Some(object(&body)))
}

/// `GET rules/<id>?view=FULL`.
pub fn get_rule_request(instance: &str, rule_id: &str) -> Request {
    Request::new("GET", instance, &rule_path(rule_id), None).with_query("view", "FULL")
}

/// `PATCH rules/<id>?updateMask=text`, with the read `etag`.
pub fn update_text_request(
    instance: &str,
    rule_id: &str,
    text: &str,
    etag: Option<&str>,
) -> Request {
    let mut body = vec![("text", Json::from(text))];
    if let Some(etag) = etag.filter(|etag| !etag.is_empty()) {
        body.push(("etag", etag.into()));
    }
    Request::new("PATCH", instance, &rule_path(rule_id), Some(object(&body)))
        .with_query("updateMask", "text")
}

/// `PATCH rules/<id>?updateMask=scope`; an empty `scope` makes the rule
/// global.
pub fn update_scope_request(
    instance: &str,
    rule_id: &str,
    scope: &str,
    etag: Option<&str>,
) -> Request {
    let mut body = vec![("scope", Json::from(scope))];
    if let Some(etag) = etag.filter(|etag| !etag.is_empty()) {
        body.push(("etag", etag.into()));
    }
    Request::new("PATCH", instance, &rule_path(rule_id), Some(object(&body)))
        .with_query("updateMask", "scope")
}

/// `GET rules/<id>/deployment`.
pub fn get_deployment_request(instance: &str, rule_id: &str) -> Request {
    Request::new(
        "GET",
        instance,
        &format!("{}/deployment", rule_path(rule_id)),
        None,
    )
}

/// `PATCH rules/<id>/deployment?updateMask=<mask>`.
pub fn deployment_request(instance: &str, rule_id: &str, state: &RunState) -> Request {
    Request::new(
        "PATCH",
        instance,
        &format!("{}/deployment", rule_path(rule_id)),
        Some(Json::Object(state.body.clone())),
    )
    .with_query("updateMask", state.mask.clone())
}

/// `PATCH rules/<id>/deployment?updateMask=archived`.
pub fn archived_request(instance: &str, rule_id: &str, archived: bool) -> Request {
    let state = RunState {
        mask: "archived".to_owned(),
        body: match object(&[("archived", Json::Bool(archived))]) {
            Json::Object(body) => body,
            _ => Object::new(),
        },
    };
    deployment_request(instance, rule_id, &state)
}

/// `DELETE rules/<id>`, never with `force`: a rule's detections are kept.
pub fn delete_request(instance: &str, rule_id: &str) -> Request {
    Request::new("DELETE", instance, &rule_path(rule_id), None)
}

/// `GET :udmSearch` with its parameters.
pub fn udm_search_request(instance: &str, params: &[(&'static str, String)]) -> Request {
    let mut request = Request::new("GET", instance, ":udmSearch", None);
    request.query.extend(params.iter().cloned());
    request
}

/// The writes a dry run shows for `rule` on `tenant` with the recorded id
/// `known`: the verify and the create of a new rule, or the text update and
/// the run state of a bound one; the disable and archive (or delete) of a
/// retiring one.
pub fn compile(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: &Json,
    known: Option<&str>,
) -> Result<Vec<Write>, CompileError> {
    let Some(block) = rule.block(PLATFORM).filter(|block| block.truthy()) else {
        return Ok(Vec::new());
    };
    let status = block
        .get("status")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let strategy = deploy::strategy(cx, DISPLAY, status)?;
    let instance = tenant_instance(tenant);
    let base = endpoint(tenant);
    let rule_id = known.unwrap_or("<rule_id>");
    let requests = match deploy::action(cx, DISPLAY, status, known)? {
        None => Vec::new(),
        Some(deploy::Action::Delete(_)) => {
            if deploy::setup_text(tenant, "deletion") == "delete" {
                vec![delete_request(&instance, rule_id)]
            } else {
                vec![
                    deployment_request(&instance, rule_id, &RunState::disabled()),
                    archived_request(&instance, rule_id, true),
                ]
            }
        }
        Some(action) => {
            let assembled = assemble(cx, rule)?;
            let state = run_state(block, strategy);
            if matches!(action, deploy::Action::Create) {
                let scope = scope_resource(
                    &instance,
                    deploy::setup(tenant, "data_access_scope").and_then(Json::as_str),
                );
                vec![
                    verify_request(&instance, &assembled.text),
                    create_request(&instance, &assembled.text, scope.as_deref()),
                    deployment_request(&instance, rule_id, &state),
                ]
            } else if strategy == StatusStrategy::Disablement {
                vec![deployment_request(&instance, rule_id, &state)]
            } else {
                vec![
                    verify_request(&instance, &assembled.text),
                    update_text_request(&instance, rule_id, &assembled.text, None),
                    deployment_request(&instance, rule_id, &state),
                ]
            }
        }
    };
    Ok(requests
        .iter()
        .map(|request| request.to_write(&base))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> Json {
        serde_json::from_str(text).unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn run_state_by_strategy() {
        let block = json(r#"{"run_frequency": "LIVE"}"#);
        let preview = run_state(&block, StatusStrategy::Preview);
        assert_eq!(preview.mask, "enabled,alerting,runFrequency");
        assert_eq!(
            Json::Object(preview.body).to_compact(),
            r#"{"enabled":true,"alerting":false,"runFrequency":"LIVE"}"#
        );
        let release = run_state(&json(r#"{"alerting": false}"#), StatusStrategy::Release);
        assert_eq!(release.mask, "enabled,alerting");
        assert_eq!(release.body.get("alerting"), Some(&Json::Bool(false)));
        assert_eq!(
            run_state(&block, StatusStrategy::Deletion),
            RunState::disabled()
        );
    }

    #[test]
    fn changes_compare_as_google_stores_them() {
        let block = json(
            r#"{"run_frequency": "LIVE_CUSTOMIZABLE", "schedule": {"late_arriving_data_adjustment": "30m"}}"#,
        );
        let state = run_state(&block, StatusStrategy::Release);
        let same = json(
            r#"{"enabled": true, "alerting": true, "runFrequency": "LIVE_CUSTOMIZABLE",
                "scheduleCustomizations": {"lateArrivingDataAdjustment": "1800.000s"}}"#,
        );
        assert_eq!(state.changes(&same), None);
        let paused = json(
            r#"{"enabled": true, "runFrequency": "LIVE_CUSTOMIZABLE",
                "scheduleCustomizations": {"lateArrivingDataAdjustment": "1800s"}}"#,
        );
        let change = state.changes(&paused).unwrap_or_else(|| panic!("a change"));
        assert_eq!(change.mask, "alerting");
        let other =
            json(r#"{"enabled": true, "alerting": true, "runFrequency": "LIVE_CUSTOMIZABLE"}"#);
        let change = state.changes(&other).unwrap_or_else(|| panic!("a change"));
        assert_eq!(change.mask, "runFrequency");
        assert!(change.body.contains_key("scheduleCustomizations"));
        // A block without a schedule clears one left on the remote rule.
        let plain = run_state(
            &json(r#"{"run_frequency": "LIVE"}"#),
            StatusStrategy::Release,
        );
        let custom = json(
            r#"{"enabled": true, "alerting": true, "runFrequency": "LIVE",
                "scheduleCustomizations": {"ensureEnrichmentCompleteness": true}}"#,
        );
        assert_eq!(
            plain.changes(&custom).map(|change| change.mask),
            Some("runFrequency".to_owned())
        );
        assert!(RunState::disabled().differs_from(&json(r#"{"enabled": true}"#)));
        assert!(!RunState::disabled().differs_from(&json("{}")));
    }

    #[test]
    fn protobuf_durations() {
        assert_eq!(protobuf_seconds(Some(&json(r#""1800s""#))), Some(1800.0));
        assert_eq!(protobuf_seconds(Some(&json(r#"" 1.5s ""#))), Some(1.5));
        assert_eq!(protobuf_seconds(Some(&json(r#""1.s""#))), None);
        assert_eq!(protobuf_seconds(Some(&json(r#""-1s""#))), None);
        assert_eq!(protobuf_seconds(Some(&json("1800"))), None);
        assert_eq!(protobuf_seconds(None), None);
    }

    #[test]
    fn scopes_and_paths() {
        let instance = instance_resource("p", "eu", "i");
        assert_eq!(instance, "projects/p/locations/eu/instances/i");
        assert_eq!(
            default_endpoint("eu"),
            "https://eu-chronicle.googleapis.com"
        );
        assert_eq!(
            scope_resource(&instance, Some(" s1/ ")).as_deref(),
            Some("projects/p/locations/eu/instances/i/dataAccessScopes/s1")
        );
        assert_eq!(
            scope_resource(
                &instance,
                Some("projects/9/locations/eu/instances/i/dataAccessScopes/s2")
            )
            .as_deref(),
            Some("projects/9/locations/eu/instances/i/dataAccessScopes/s2")
        );
        assert_eq!(scope_resource(&instance, Some("")), None);
        assert_eq!(scope_resource(&instance, None), None);
        assert_eq!(scope_id("a/dataAccessScopes/s2"), "s2");
        assert_eq!(scope_id(""), "");
        assert_eq!(rule_path("ru_a/b c"), "rules/ru_a%2Fb%20c");
    }

    #[test]
    fn requests_as_the_fixtures_hold_them() {
        let instance = instance_resource("p", "eu", "i");
        let request = update_text_request(&instance, "ru_1", "t", Some("e"));
        assert_eq!(
            request.to_json().to_compact(),
            r#"{"method":"PATCH","path":"/v1/projects/p/locations/eu/instances/i/rules/ru_1","query":{"updateMask":"text"},"body":{"text":"t","etag":"e"}}"#
        );
        let write = request.to_write("https://x/");
        assert_eq!(
            write.url,
            "https://x/v1/projects/p/locations/eu/instances/i/rules/ru_1?updateMask=text"
        );
        assert_eq!(
            update_scope_request(&instance, "ru_1", "", None).body,
            Some(json(r#"{"scope": ""}"#))
        );
        assert_eq!(
            get_rule_request(&instance, "ru_1").query,
            [("view", "FULL".to_owned())]
        );
        assert_eq!(
            get_deployment_request(&instance, "ru_1").path,
            "/v1/projects/p/locations/eu/instances/i/rules/ru_1/deployment"
        );
        assert_eq!(delete_request(&instance, "ru_1").method, "DELETE");
        let search = udm_search_request(&instance, &[("query", "x".to_owned())]);
        assert_eq!(
            search.path,
            "/v1/projects/p/locations/eu/instances/i:udmSearch"
        );
        assert_eq!(
            create_request(&instance, "t", Some("s")).body,
            Some(json(r#"{"text": "t", "scope": "s"}"#))
        );
    }
}
