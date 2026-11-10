//! Elastic Security: a rule as a Detection Engine rule body
//! (`platforms/elastic/compile.py` `compile_rule`, `attack.py`
//! `resolve_elastic_threat`), in the oracle's key order.
//!
//! The oracle compiles the rule's model dump (`by_alias`, `exclude_none`): the
//! nested models' defaults are present, and their keys are in the model's
//! field order whatever order the file writes them in. [`model_order`] puts
//! those back, so the body does not depend on how the YAML is laid out.

use indexmap::IndexMap;

use crate::Context;
use crate::attack::{TACTIC_ORDER, non_enterprise, tactic, techniques};
use crate::duration;
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;

/// The platform's display name, in messages.
pub const DISPLAY: &str = "Elastic";

/// Fields the server owns: never sent.
const SERVER_OWNED: [&str; 11] = [
    "id",
    "version",
    "revision",
    "created_at",
    "created_by",
    "updated_at",
    "updated_by",
    "execution_summary",
    "immutable",
    "rule_source",
    "outcome",
];

/// `response.alert_severity` → the Elastic severity and its default risk score.
const SEVERITY_TABLE: [(&str, &str, i64); 5] = [
    ("Informational", "low", 1),
    ("Low", "low", 21),
    ("Medium", "medium", 47),
    ("High", "high", 73),
    ("Critical", "critical", 99),
];

/// A nested model's fields, in its declaration order, each with its default
/// when it has one that is not `None`.
type Fields = &'static [(&'static str, Option<fn() -> Json>)];

fn equals() -> Json {
    "equals".into()
}
fn empty_text() -> Json {
    "".into()
}
fn mapping() -> Json {
    "mapping".into()
}
fn star() -> Json {
    "*".into()
}
fn no() -> Json {
    Json::Bool(false)
}
fn suppress() -> Json {
    "suppress".into()
}
fn empty_list() -> Json {
    Json::Array(Vec::new())
}

const SEVERITY_MAPPING: Fields = &[
    ("field", None),
    ("value", None),
    ("operator", Some(equals)),
    ("severity", None),
];
const RISK_MAPPING: Fields = &[
    ("field", None),
    ("operator", Some(equals)),
    ("value", Some(empty_text)),
];
const THREAT_ENTRY: Fields = &[
    ("field", None),
    ("value", None),
    ("type", Some(mapping)),
    ("negate", None),
];
const INTEGRATION: Fields = &[
    ("package", None),
    ("integration", None),
    ("version", Some(star)),
];
const FILTER: Fields = &[
    ("field", None),
    ("value", None),
    ("negate", Some(no)),
    ("meta", None),
    ("query", None),
];
const EXCEPTION_LIST: Fields = &[
    ("id", None),
    ("list_id", None),
    ("namespace_type", None),
    ("type", None),
];
const CARDINALITY: Fields = &[("field", None), ("value", None)];
const SUPPRESSION: Fields = &[
    ("group_by", None),
    ("duration", None),
    ("missing_fields_strategy", Some(suppress)),
];
const THRESHOLD: Fields = &[
    ("field", Some(empty_list)),
    ("value", None),
    ("cardinality", None),
];

/// An object as the oracle's model dump holds it: the model's fields in their
/// order, defaults filled in, `null` left out.
pub fn model_order(value: &Json, fields: Fields) -> Json {
    let Some(object) = value.as_object() else {
        return value.clone();
    };
    let mut out = Object::new();
    for (name, default) in fields {
        match object.get(*name) {
            Some(Json::Null) | None => {
                if let Some(default) = default {
                    out.insert((*name).to_owned(), default());
                }
            }
            Some(value) => {
                out.insert((*name).to_owned(), value.clone());
            }
        }
    }
    Json::Object(out)
}

/// Each object of a list in model order.
fn list_in_order(value: Option<&Json>, fields: Fields) -> Vec<Json> {
    match value {
        Some(Json::Array(items)) => items.iter().map(|item| model_order(item, fields)).collect(),
        _ => Vec::new(),
    }
}

/// The value at `key`, unless absent or `null` (the model dump drops `None`).
fn get<'j>(object: &'j Json, key: &str) -> Option<&'j Json> {
    object.get(key).filter(|value| !value.is_null())
}

fn text_of(value: &Json) -> Result<&str, String> {
    value
        .as_str()
        .ok_or_else(|| format!("Duration must be a string, got {}", python_type(value)))
}

fn python_type(value: &Json) -> &'static str {
    match value {
        Json::Null => "NoneType",
        Json::Bool(_) => "bool",
        Json::Int(_) => "int",
        Json::Float(_) => "float",
        Json::Str(_) => "str",
        Json::Array(_) => "list",
        Json::Object(_) => "dict",
    }
}

fn failed(message: String) -> CompileError {
    CompileError::failed(DISPLAY, &message)
}

/// The phrase filter of the `field`/`value` shorthand.
fn phrase(field: &Json, value: &Json, negate: bool) -> Json {
    let field_name = match field {
        Json::Str(text) => text.clone(),
        other => other.to_compact(),
    };
    let mut params = Object::new();
    params.insert("query".into(), value.clone());
    let mut meta = Object::new();
    meta.insert("key".into(), field.clone());
    meta.insert("negate".into(), Json::Bool(negate));
    meta.insert("disabled".into(), Json::Bool(false));
    meta.insert("type".into(), "phrase".into());
    meta.insert("params".into(), Json::Object(params));
    let mut matched = Object::new();
    matched.insert(field_name, value.clone());
    let mut query = Object::new();
    query.insert("match_phrase".into(), Json::Object(matched));
    let mut out = Object::new();
    out.insert("meta".into(), Json::Object(meta));
    out.insert("query".into(), Json::Object(query));
    Json::Object(out)
}

/// A filter entry (`compile_filter`): the `field`/`value` shorthand becomes a
/// phrase filter; anything else is sent as it is. `fields` puts a model's
/// entry in its model order first; a plain mapping (`threat.filters`) is sent
/// as written.
fn compile_filter(entry: &Json, fields: Option<Fields>) -> Json {
    let entry = match fields {
        Some(fields) => model_order(entry, fields),
        None => entry.clone(),
    };
    if let (Some(field), None, None) = (
        get(&entry, "field"),
        get(&entry, "meta"),
        get(&entry, "query"),
    ) {
        let value = entry.get("value").cloned().unwrap_or(Json::Null);
        let negate = entry.get("negate").is_some_and(Json::truthy);
        return phrase(field, &value, negate);
    }
    entry
}

/// A response action (`compile_response`).
fn compile_response(action: &Json) -> Json {
    if let Some(command) = action.get("endpoint") {
        let mut params = Object::new();
        params.insert("command".into(), command.clone());
        if let Some(comment) = action.get("comment").filter(|value| value.truthy()) {
            params.insert("comment".into(), comment.clone());
        }
        if let Some(field) = action.get("field").filter(|value| value.truthy()) {
            let mut config = Object::new();
            config.insert("field".into(), field.clone());
            config.insert("overwrite".into(), Json::Bool(false));
            params.insert("config".into(), Json::Object(config));
        } else if matches!(command.as_str(), Some("kill-process" | "suspend-process")) {
            let mut config = Object::new();
            config.insert("field".into(), "process.entity_id".into());
            config.insert("overwrite".into(), Json::Bool(true));
            params.insert("config".into(), Json::Object(config));
        }
        let mut out = Object::new();
        out.insert("action_type_id".into(), ".endpoint".into());
        out.insert("params".into(), Json::Object(params));
        return Json::Object(out);
    }
    if let Some(osquery) = action.get("osquery") {
        let mut out = Object::new();
        out.insert("action_type_id".into(), ".osquery".into());
        out.insert("params".into(), osquery.clone());
        return Json::Object(out);
    }
    action.clone()
}

/// An integration: a package name, or a mapping with its version (`*` when
/// unset).
fn related_integration(entry: &Json) -> Json {
    match entry {
        Json::Str(package) => {
            let mut out = Object::new();
            out.insert("package".into(), package.clone().into());
            out.insert("version".into(), "*".into());
            Json::Object(out)
        }
        other => model_order(other, INTEGRATION),
    }
}

/// The rule's alert level (`_alert_level`).
fn alert_level(block: &Json, rule: &Rule) -> &'static str {
    let response_severity = || {
        rule.response()
            .and_then(|response| response.get("alert_severity"))
            .and_then(Json::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    };
    let raw = match block.get("severity") {
        Some(Json::Object(severity)) => severity
            .get("default")
            .and_then(Json::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
            .or_else(response_severity)
            .unwrap_or_else(|| "Informational".to_owned()),
        Some(Json::Str(text)) => text.clone(),
        _ => response_severity().unwrap_or_else(|| "Informational".to_owned()),
    };
    let key = raw.trim().to_lowercase();
    SEVERITY_TABLE
        .iter()
        .find(|(name, _, _)| name.to_lowercase() == key)
        .map_or("Informational", |(name, _, _)| *name)
}

/// The tenant's `setup` values the compiler reads; `None` compiles as no
/// tenant does (`index` and `tags` unset, suppression on).
#[derive(Debug, Clone, Default)]
pub struct Setup {
    /// `index`.
    pub index: Option<Vec<String>>,
    /// `tags`.
    pub tags: Vec<String>,
    /// `suppression`: whether the tenant sends alert suppression.
    pub suppression: bool,
}

impl Setup {
    /// The setup of a configured tenant (`[[tenants]]` of
    /// `platforms/elastic.toml`): `index` and `tags` when lists of strings,
    /// `suppression` unless `false`.
    pub fn from_tenant(tenant: &Json) -> Self {
        let setup = tenant.get("setup");
        let list = |key: &str| match setup.and_then(|setup| setup.get(key)) {
            Some(Json::Array(items)) => Some(
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        };
        Self {
            index: list("index"),
            tags: list("tags").unwrap_or_default(),
            suppression: !matches!(
                setup.and_then(|setup| setup.get("suppression")),
                Some(Json::Bool(false))
            ),
        }
    }

    /// What a rule compiles with when no tenant is named.
    pub fn none() -> Self {
        Self {
            index: None,
            tags: Vec::new(),
            suppression: true,
        }
    }
}

/// Pushes each string not already there.
fn extend_unique(into: &mut Vec<String>, items: impl IntoIterator<Item = String>) {
    for item in items {
        if !into.contains(&item) {
            into.push(item);
        }
    }
}

fn strings(value: Option<&Json>) -> Vec<String> {
    match value {
        Some(Json::Array(items)) => items
            .iter()
            .map(|item| match item {
                Json::Str(text) => text.clone(),
                other => other.to_compact(),
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// The Detection Engine body of `rule` for a tenant with `setup`.
pub fn compile(cx: &Context<'_>, rule: &Rule, setup: &Setup) -> Result<Json, CompileError> {
    let empty = Json::Object(Object::new());
    let block = rule.block("elastic").unwrap_or(&empty);
    let rule_type = get(block, "type")
        .and_then(Json::as_str)
        .unwrap_or("query")
        .to_owned();
    let status = get(block, "status")
        .and_then(Json::as_str)
        .ok_or_else(|| failed("'status'".to_owned()))?;
    let strategy = cx
        .statuses
        .strategy(status)
        .map_err(|error| failed(error.exception_text()))?;
    let enabled = strategy != StatusStrategy::Disablement;
    let level = alert_level(block, rule);
    let (_, severity, default_risk) = SEVERITY_TABLE
        .iter()
        .find(|(name, _, _)| *name == level)
        .copied()
        .unwrap_or(("Informational", "low", 1));
    let mut risk_score = Json::Int(default_risk);
    let risk = get(block, "risk");
    match risk {
        Some(Json::Int(score)) => risk_score = Json::Int(*score),
        Some(Json::Object(risk)) => {
            if let Some(score) = risk.get("score").filter(|score| !score.is_null()) {
                risk_score = score.clone();
            }
        }
        _ => {}
    }
    let scheduling = get(block, "scheduling")
        .cloned()
        .unwrap_or_else(|| empty.clone());
    let interval = get(&scheduling, "interval")
        .cloned()
        .unwrap_or_else(|| "5m".into());
    let lookback = get(&scheduling, "lookback")
        .cloned()
        .unwrap_or_else(|| "1m".into());
    let interval = text_of(&interval).map_err(failed)?;
    let lookback = text_of(&lookback).map_err(failed)?;
    let window = duration::elastic_format(
        duration::elastic_seconds(interval, false).map_err(failed)?
            + duration::elastic_seconds(lookback, true).map_err(failed)?,
    );
    let name = get(block, "name")
        .filter(|name| name.truthy())
        .or_else(|| rule.data.get("name").filter(|name| name.truthy()))
        .cloned()
        .unwrap_or_else(|| "".into());
    let description = rule.description().trim_end().to_owned();

    let mut body = Object::new();
    body.insert("rule_id".into(), rule.uuid.clone().into());
    body.insert("type".into(), rule_type.clone().into());
    body.insert("name".into(), name);
    body.insert("description".into(), description.into());
    body.insert("enabled".into(), Json::Bool(enabled));
    body.insert("severity".into(), severity.into());
    body.insert("risk_score".into(), risk_score);
    body.insert(
        "interval".into(),
        duration::elastic_date_math(interval)
            .map_err(failed)?
            .into(),
    );
    body.insert("from".into(), format!("now-{window}").into());
    body.insert("to".into(), "now".into());

    match rule_type.as_str() {
        "eql" => {
            body.insert("language".into(), "eql".into());
        }
        "esql" => {
            body.insert("language".into(), "esql".into());
        }
        "machine_learning" => {}
        _ => {
            let language = get(block, "language")
                .filter(|language| language.truthy())
                .cloned()
                .unwrap_or_else(|| "kuery".into());
            body.insert("language".into(), language);
        }
    }
    if let Some(query) = get(block, "query")
        && rule_type != "machine_learning"
    {
        let query = query
            .as_str()
            .ok_or_else(|| failed("'query' is not a string".to_owned()))?;
        body.insert("query".into(), query.trim_end().into());
    }
    if let Some(view) = get(block, "data_view_id").filter(|view| view.truthy()) {
        body.insert("data_view_id".into(), view.clone());
    } else if rule_type != "esql" && rule_type != "machine_learning" {
        let index = match get(block, "index").filter(|index| index.truthy()) {
            Some(index) => Some(index.clone()),
            None => setup.index.clone().map(Json::from),
        };
        if let Some(Json::Array(items)) = index
            && !items.is_empty()
        {
            body.insert("index".into(), Json::Array(items));
        }
    }
    if let Some(Json::Array(filters)) = get(block, "filters")
        && rule_type != "esql"
        && rule_type != "machine_learning"
    {
        body.insert(
            "filters".into(),
            Json::Array(
                filters
                    .iter()
                    .map(|entry| compile_filter(entry, Some(FILTER)))
                    .collect(),
            ),
        );
    }
    if let Some(threshold) = get(block, "threshold") {
        let threshold = model_order(threshold, THRESHOLD);
        let mut out = Object::new();
        out.insert(
            "field".into(),
            threshold.get("field").cloned().unwrap_or_else(empty_list),
        );
        out.insert(
            "value".into(),
            threshold.get("value").cloned().unwrap_or(Json::Null),
        );
        if let Some(cardinality) = threshold.get("cardinality").filter(|c| c.truthy()) {
            out.insert(
                "cardinality".into(),
                Json::Array(vec![model_order(cardinality, CARDINALITY)]),
            );
        }
        body.insert("threshold".into(), Json::Object(out));
    }
    if let Some(new_terms) = get(block, "new_terms") {
        body.insert(
            "new_terms_fields".into(),
            new_terms.get("fields").cloned().unwrap_or_else(empty_list),
        );
        let start = new_terms
            .get("history_window_start")
            .ok_or_else(|| failed("'history_window_start'".to_owned()))?;
        let start = text_of(start).map_err(failed)?;
        body.insert(
            "history_window_start".into(),
            format!(
                "now-{}",
                duration::elastic_date_math(start).map_err(failed)?
            )
            .into(),
        );
    }
    if let Some(eql) = get(block, "eql") {
        for key in [
            "timestamp_field",
            "event_category_override",
            "tiebreaker_field",
        ] {
            if let Some(value) = get(eql, key) {
                body.insert(key.into(), value.clone());
            }
        }
    }
    if let Some(threat) = get(block, "threat") {
        body.insert(
            "threat_index".into(),
            threat.get("index").cloned().unwrap_or_else(empty_list),
        );
        body.insert(
            "threat_query".into(),
            threat.get("query").cloned().unwrap_or(Json::Null),
        );
        if let Some(language) = get(threat, "language").filter(|value| value.truthy()) {
            body.insert("threat_language".into(), language.clone());
        }
        if let Some(Json::Array(filters)) = get(threat, "filters") {
            body.insert(
                "threat_filters".into(),
                Json::Array(
                    filters
                        .iter()
                        .map(|entry| compile_filter(entry, None))
                        .collect(),
                ),
            );
        }
        if let Some(path) = get(threat, "indicator_path") {
            body.insert("threat_indicator_path".into(), path.clone());
        }
        let groups = match threat.get("mapping") {
            Some(Json::Array(groups)) => groups
                .iter()
                .map(|group| {
                    let entries = list_in_order(group.get("entries"), THREAT_ENTRY)
                        .into_iter()
                        .map(|entry| {
                            let mut out = Object::new();
                            out.insert(
                                "type".into(),
                                entry.get("type").cloned().unwrap_or_else(mapping),
                            );
                            if let Some(object) = entry.as_object() {
                                for (key, value) in object {
                                    if !value.is_null() {
                                        out.insert(key.clone(), value.clone());
                                    }
                                }
                            }
                            Json::Object(out)
                        })
                        .collect();
                    let mut out = Object::new();
                    out.insert("entries".into(), Json::Array(entries));
                    Json::Object(out)
                })
                .collect(),
            _ => Vec::new(),
        };
        body.insert("threat_mapping".into(), Json::Array(groups));
    }
    if let Some(ml) = get(block, "machine_learning") {
        body.insert(
            "machine_learning_job_id".into(),
            ml.get("job_id").cloned().unwrap_or(Json::Null),
        );
        body.insert(
            "anomaly_threshold".into(),
            ml.get("anomaly_threshold").cloned().unwrap_or(Json::Null),
        );
    }
    if let Some(Json::Object(severity)) = get(block, "severity")
        && let Some(Json::Array(mapping)) = severity.get("mapping")
        && !mapping.is_empty()
    {
        body.insert(
            "severity_mapping".into(),
            Json::Array(
                mapping
                    .iter()
                    .map(|entry| model_order(entry, SEVERITY_MAPPING))
                    .collect(),
            ),
        );
    }
    if let Some(Json::Object(risk)) = risk
        && let Some(Json::Array(mapping)) = risk.get("mapping")
        && !mapping.is_empty()
    {
        body.insert(
            "risk_score_mapping".into(),
            Json::Array(
                mapping
                    .iter()
                    .map(|entry| model_order(entry, RISK_MAPPING))
                    .collect(),
            ),
        );
    }
    if let Some(overrides) = get(block, "overrides") {
        for (field, key) in [
            ("name", "rule_name_override"),
            ("timestamp", "timestamp_override"),
            ("disable_fallback", "timestamp_override_fallback_disabled"),
        ] {
            if let Some(value) = get(overrides, field) {
                body.insert(key.into(), value.clone());
            }
        }
    }
    if let Some(actions) = get(block, "actions").filter(|actions| actions.as_object().is_some()) {
        if let Some(notify) = get(actions, "notify") {
            body.insert("actions".into(), notify.clone());
        }
        if let Some(Json::Array(respond)) = get(actions, "respond") {
            body.insert(
                "response_actions".into(),
                Json::Array(respond.iter().map(compile_response).collect()),
            );
        }
        if let Some(timeline) = get(actions, "timeline") {
            if let Some(id) = get(timeline, "id") {
                body.insert("timeline_id".into(), id.clone());
            }
            if let Some(title) = get(timeline, "title") {
                body.insert("timeline_title".into(), title.clone());
            }
        }
    }
    if let Some(max) = get(&scheduling, "max_alerts") {
        body.insert("max_signals".into(), max.clone());
    }
    if let Some(suppression) = get(block, "suppression")
        && setup.suppression
    {
        let suppression = model_order(suppression, SUPPRESSION);
        let mut out = Object::new();
        if rule_type != "threshold" {
            let group_by = suppression
                .get("group_by")
                .filter(|value| !value.is_null())
                .ok_or_else(|| failed("'NoneType' object is not iterable".to_owned()))?;
            out.insert("group_by".into(), group_by.clone());
        }
        if let Some(window) = suppression.get("duration").filter(|value| value.truthy()) {
            let window = text_of(window).map_err(failed)?;
            let (amount, unit) = duration::elastic_amount(window, "hms").map_err(failed)?;
            let mut duration = Object::new();
            duration.insert(
                "value".into(),
                Json::Int(i64::try_from(amount).unwrap_or(i64::MAX)),
            );
            duration.insert("unit".into(), unit.to_string().into());
            out.insert("duration".into(), Json::Object(duration));
        }
        if rule_type != "threshold" {
            out.insert(
                "missing_fields_strategy".into(),
                suppression
                    .get("missing_fields_strategy")
                    .cloned()
                    .unwrap_or_else(suppress),
            );
        }
        body.insert("alert_suppression".into(), Json::Object(out));
    }
    if let Some(fields) = get(block, "highlighted_fields").filter(|value| value.truthy()) {
        let mut investigation = Object::new();
        investigation.insert("field_names".into(), fields.clone());
        body.insert("investigation_fields".into(), Json::Object(investigation));
    }
    if let Some(Json::Array(required)) = get(block, "required_fields")
        && !required.is_empty()
    {
        let mut fields: Vec<(String, Json)> = required
            .iter()
            .map(|field| {
                let name = field.get("name").cloned().unwrap_or(Json::Null);
                let mut out = Object::new();
                out.insert("name".into(), name.clone());
                out.insert(
                    "type".into(),
                    field.get("type").cloned().unwrap_or(Json::Null),
                );
                (
                    name.as_str().unwrap_or_default().to_owned(),
                    Json::Object(out),
                )
            })
            .collect();
        // Python's sort is stable, as `sort_by` is.
        fields.sort_by(|a, b| a.0.cmp(&b.0));
        body.insert(
            "required_fields".into(),
            Json::Array(fields.into_iter().map(|(_, field)| field).collect()),
        );
    }
    if let Some(Json::Array(integrations)) = get(block, "integration")
        && !integrations.is_empty()
    {
        body.insert(
            "related_integrations".into(),
            Json::Array(integrations.iter().map(related_integration).collect()),
        );
    }
    let guide = get(block, "guide");
    if let Some(setup_text) = guide
        .and_then(|guide| guide.get("setup"))
        .and_then(Json::as_str)
        .filter(|text| !text.is_empty())
    {
        body.insert("setup".into(), setup_text.trim_end().into());
    }
    if let Some(positives) = get(block, "false_positives").filter(|value| value.truthy()) {
        body.insert("false_positives".into(), positives.clone());
    }
    if get(block, "building_block").is_some_and(Json::truthy) {
        body.insert("building_block_type".into(), "default".into());
    }
    if let Some(exceptions) = get(block, "exceptions") {
        let mut lists = list_in_order(get(exceptions, "lists"), EXCEPTION_LIST);
        let mut endpoint = Object::new();
        endpoint.insert("id".into(), "endpoint_list".into());
        endpoint.insert("list_id".into(), "endpoint_list".into());
        endpoint.insert("namespace_type".into(), "agnostic".into());
        endpoint.insert("type".into(), "endpoint".into());
        let endpoint = Json::Object(endpoint);
        if get(exceptions, "endpoint").is_some_and(Json::truthy) && !lists.contains(&endpoint) {
            lists.push(endpoint);
        }
        if !lists.is_empty() {
            body.insert("exceptions_list".into(), Json::Array(lists));
        }
    }
    let mut tags = vec!["OpenTide".to_owned()];
    extend_unique(&mut tags, setup.tags.iter().cloned());
    extend_unique(&mut tags, strings(get(block, "tags")));
    body.insert("tags".into(), tags.into());

    let metadata = rule.data.get("metadata");
    let mut authors: Vec<String> = Vec::new();
    let author = metadata.and_then(|metadata| get(metadata, "author"));
    let contributors = strings(metadata.and_then(|metadata| get(metadata, "contributors")));
    let candidates = author
        .into_iter()
        .map(|author| match author {
            Json::Str(text) => text.clone(),
            other => other.to_compact(),
        })
        .chain(contributors)
        .filter(|name| !name.is_empty());
    extend_unique(&mut authors, candidates);
    if !authors.is_empty() {
        body.insert("author".into(), authors.into());
    }
    if let Some(Json::Object(public)) = rule
        .data
        .get("references")
        .and_then(|references| get(references, "public"))
        && !public.is_empty()
    {
        let mut keys: Vec<&String> = public.keys().collect();
        if keys.iter().all(|key| key.trim().parse::<i64>().is_ok()) {
            keys.sort_by_key(|key| key.trim().parse::<i64>().unwrap_or_default());
        } else {
            keys.sort();
        }
        body.insert(
            "references".into(),
            Json::Array(keys.into_iter().map(|key| public[key].clone()).collect()),
        );
    }
    let analysis = rule
        .response()
        .and_then(|response| response.get("procedure"))
        .and_then(|procedure| procedure.get("analysis"))
        .filter(|value| value.truthy());
    let note = guide
        .and_then(|guide| guide.get("investigation"))
        .filter(|value| value.truthy())
        .or(analysis);
    if let Some(note) = note {
        let text = match note {
            Json::Str(text) => text.clone(),
            other => other.to_compact(),
        };
        body.insert("note".into(), text.trim_end().into());
    }
    let threat = threat(cx, rule);
    if !threat.is_empty() {
        body.insert("threat".into(), Json::Array(threat));
    }
    body.retain(|key, _| !SERVER_OWNED.contains(&key.as_str()));
    Ok(Json::Object(body))
}

/// The rule's techniques, its own and those it inherits, de-duplicated.
pub fn rule_techniques(cx: &Context<'_>, rule: &Rule) -> Vec<String> {
    let mut raw = strings(rule.data.get("techniques"));
    if rule.data.get("detection_model").is_some_and(Json::truthy)
        && !rule.uuid.is_empty()
        && let Ok(inherited) = techniques(cx.index, &rule.uuid)
    {
        raw.extend(inherited);
    }
    let mut unique = Vec::with_capacity(raw.len());
    extend_unique(&mut unique, raw);
    unique
}

/// The `threat` array (`resolve_elastic_threat`): tactics in matrix order,
/// each with its parent techniques sorted and their sub-techniques.
pub fn threat(cx: &Context<'_>, rule: &Rule) -> Vec<Json> {
    let techniques = rule_techniques(cx, rule);
    // stage -> parent -> sub-techniques
    let mut grouped: IndexMap<&'static str, IndexMap<String, Vec<String>>> = IndexMap::new();
    for id in &techniques {
        let Some(name) = cx.attack.name(id) else {
            continue;
        };
        if non_enterprise(name) {
            continue;
        }
        let parent = id.split('.').next().unwrap_or(id).to_owned();
        for stage in cx.attack.stages(id) {
            let Some((stage, _)) = tactic(&stage) else {
                continue;
            };
            let subs = grouped
                .entry(stage)
                .or_default()
                .entry(parent.clone())
                .or_default();
            if id.contains('.') && !subs.contains(id) {
                subs.push(id.clone());
            }
        }
    }
    let mut threat = Vec::new();
    for (stage, tactic_id) in TACTIC_ORDER {
        let Some(parents) = grouped.get(stage) else {
            continue;
        };
        let mut parents: Vec<(String, Vec<String>)> = parents
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        parents.sort_by(|a, b| a.0.cmp(&b.0));
        let mut techniques_out = Vec::new();
        for (parent, mut subs) in parents {
            let Some(parent_name) = cx.attack.name(&parent) else {
                continue;
            };
            let parent_name = parent_name.to_owned();
            let link = cx.attack.link(&parent).map_or_else(
                || format!("https://attack.mitre.org/techniques/{parent}"),
                str::to_owned,
            );
            let mut technique = Object::new();
            technique.insert("id".into(), parent.clone().into());
            technique.insert("name".into(), parent_name.clone().into());
            technique.insert("reference".into(), link.into());
            subs.sort();
            let prefix = format!("{parent_name}: ");
            let sub_list: Vec<Json> = subs
                .iter()
                .filter_map(|sub| {
                    let name = cx.attack.name(sub)?;
                    let name = name.strip_prefix(&prefix).unwrap_or(name).to_owned();
                    let link = cx.attack.link(sub).map_or_else(
                        || {
                            format!(
                                "https://attack.mitre.org/techniques/{}",
                                sub.replace('.', "/")
                            )
                        },
                        str::to_owned,
                    );
                    let mut out = Object::new();
                    out.insert("id".into(), sub.clone().into());
                    out.insert("name".into(), name.into());
                    out.insert("reference".into(), link.into());
                    Some(Json::Object(out))
                })
                .collect();
            if !sub_list.is_empty() {
                technique.insert("subtechnique".into(), Json::Array(sub_list));
            }
            techniques_out.push(Json::Object(technique));
        }
        if !techniques_out.is_empty() {
            let mut tactic_object = Object::new();
            tactic_object.insert("id".into(), tactic_id.into());
            tactic_object.insert("name".into(), stage.into());
            tactic_object.insert(
                "reference".into(),
                format!("https://attack.mitre.org/tactics/{tactic_id}/").into(),
            );
            let mut entry = Object::new();
            entry.insert("framework".into(), "MITRE ATT&CK".into());
            entry.insert("tactic".into(), Json::Object(tactic_object));
            entry.insert("technique".into(), Json::Array(techniques_out));
            threat.push(Json::Object(entry));
        }
    }
    threat
}
