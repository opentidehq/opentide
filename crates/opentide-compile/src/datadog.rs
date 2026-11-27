//! Datadog Cloud SIEM (RFC `docs/internal/rfc-datadog-cloud-siem.md` §7): an
//! opentide rule's `datadog` block as the body of a v2 Security Monitoring
//! rule.
//!
//! The author writes the queries, the detection, the cases and the signal
//! settings; the rest is derived from the rule: the message (§7.3), when the
//! block has none, and the tags (§7.4). The same body is sent to
//! `POST /security_monitoring/rules/validation`, to `POST
//! /security_monitoring/rules` (create) and, with the `version` the `GET`
//! returned, to `PUT /security_monitoring/rules/{id}` (update). Keys are
//! built in the order of the RFC's §7.2; `tests/fixtures/datadog/` holds the
//! rules.
//!
//! Facts the RFC marks unverified are not filled in: the anomaly options are
//! sent only as the block sets them, `detectIpTransition` only when `true`,
//! and `learningMethod: duration` is the one `new_value` learning the RFC
//! maps.

use opentide_schema::objects::platform::datadog::{
    DEFAULT_KEEP_ALIVE, DEFAULT_MAX_DURATION, DEFAULT_METHOD, DEFAULT_NEW_VALUE_LEARNING,
    DEFAULT_WINDOW, NOTIFICATION_ALIAS, anomaly_learning_hours, bucket_seconds, days,
    default_query_name, tag_problem, window_seconds,
};

use crate::Context;
use crate::attack;
use crate::deploy;
use crate::elastic::rule_techniques;
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;

/// The platform's identifier.
pub const PLATFORM: &str = "datadog";
/// The platform's name in messages.
pub const DISPLAY: &str = "Datadog Cloud SIEM";
/// The detection rules endpoint, relative to the API base URL.
pub const RULES_PATH: &str = "/api/v2/security_monitoring/rules";
/// The rule validation endpoint.
pub const VALIDATION_PATH: &str = "/api/v2/security_monitoring/rules/validation";
/// The Logs Search endpoint.
pub const LOGS_SEARCH_PATH: &str = "/api/v2/logs/events/search";
/// The rule type of every 1.0 block.
pub const RULE_TYPE: &str = "log_detection";
/// A case's status when neither the case nor `response.alert_severity`
/// names one.
pub const DEFAULT_SEVERITY: &str = "info";
/// The tag a `PREVIEW` deploy adds (RFC §8.3).
pub const PREVIEW_TAG: &str = "opentide_strategy:preview";
/// The tag that names the opentide rule (advisory only: the deployment state
/// is the proof).
pub const UUID_TAG: &str = "opentide_uuid";
/// The field impossible travel measures.
pub const GEO_FIELD: &str = "@network.client.geoip";
/// The minutes the `--live` search of a query looks back.
pub const LIVE_WINDOW_MINUTES: i64 = 1;
/// The most events Logs Search returns in a page.
pub const PAGE_LIMIT: usize = 5000;

/// `response.alert_severity` → a case's `status` (RFC §7.1).
fn alert_severity(name: &str) -> Option<&'static str> {
    match name {
        "informational" => Some("info"),
        "low" => Some("low"),
        "medium" => Some("medium"),
        "high" => Some("high"),
        "critical" => Some("critical"),
        _ => None,
    }
}

/// `detection.method` → `options.detectionMethod`.
fn detection_method(method: &str) -> &str {
    match method {
        "anomaly" => "anomaly_detection",
        other => other,
    }
}

/// `queries[].from` → `dataSource`.
fn data_source(from: &str) -> &str {
    match from {
        "signals" => "security_signals",
        other => other,
    }
}

/// What a block deploys on one tenant.
#[derive(Debug, Clone, PartialEq)]
pub struct DatadogRule {
    /// The opentide rule's UUID.
    pub uuid: String,
    /// The Datadog rule name.
    pub name: String,
    /// The validation, create and update body.
    pub body: Json,
}

/// A key of a block table, a null read as the key left out.
fn field<'j>(table: &'j Json, key: &str) -> Option<&'j Json> {
    table.get(key).filter(|value| !value.is_null())
}

/// A string field that is set and not empty.
fn text<'j>(table: &'j Json, key: &str) -> Option<&'j str> {
    field(table, key)
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
}

/// A window-valued field's text: a string, or the number `0`.
fn window_text<'j>(table: &'j Json, key: &str) -> Option<&'j str> {
    match field(table, key) {
        Some(Json::Str(text)) => Some(text),
        Some(Json::Int(0)) => Some("0"),
        _ => None,
    }
}

/// A list field's items, or none.
fn items<'j>(table: &'j Json, key: &str) -> &'j [Json] {
    match field(table, key) {
        Some(Json::Array(items)) => items,
        _ => &[],
    }
}

/// A list of strings, as the API takes it.
fn strings(values: &[Json]) -> Json {
    Json::Array(
        values
            .iter()
            .map(|value| deploy::text(value).into())
            .collect(),
    )
}

fn failed(text: &str) -> CompileError {
    CompileError::failed(DISPLAY, text)
}

/// The rule's Datadog block, or the error naming the rule.
fn block_of(rule: &Rule) -> Result<&Json, CompileError> {
    rule.block(PLATFORM).ok_or_else(|| {
        failed(&format!(
            "Rule {} ({}) has no datadog block",
            rule.uuid, rule.name
        ))
    })
}

/// The strategy the block's status maps to.
pub fn strategy(cx: &Context<'_>, rule: &Rule) -> Result<StatusStrategy, CompileError> {
    let status = block_of(rule)?
        .get("status")
        .map_or_else(|| "null".to_owned(), deploy::text);
    deploy::strategy(cx, DISPLAY, &status)
}

/// The block's `name`, else the opentide rule's.
pub fn rule_name<'a>(rule_name: &'a str, block: &'a Json) -> &'a str {
    text(block, "name").unwrap_or(rule_name)
}

/// The block's method, as written (`threshold` when unset).
fn method(block: &Json) -> &str {
    field(block, "detection")
        .and_then(|detection| text(detection, "method"))
        .unwrap_or(DEFAULT_METHOD)
}

/// Seconds of a window-valued text, or the error naming the key.
fn seconds(value: &str, key: &str) -> Result<Json, CompileError> {
    window_seconds(value)
        .map(Json::Int)
        .ok_or_else(|| failed(&format!("{key} {value:?} is not a Datadog window")))
}

fn query(index: usize, query: &Json, method: &str) -> Json {
    let mut out = Object::new();
    let new_value = items(query, "new_value");
    let is_new_value = field(query, "new_value").is_some();
    if !is_new_value {
        let name = text(query, "name").map_or_else(|| default_query_name(index), str::to_owned);
        out.insert("name".into(), name.into());
    }
    let search = field(query, "query").map(deploy::text).unwrap_or_default();
    out.insert("query".into(), search.trim().into());
    out.insert(
        "dataSource".into(),
        data_source(text(query, "from").unwrap_or("logs")).into(),
    );
    let (aggregation, metrics, distinct): (&str, Option<Json>, Option<Json>) =
        if method == "impossible_travel" {
            ("geo_data", Some(vec![GEO_FIELD.to_owned()].into()), None)
        } else if is_new_value {
            ("new_value", Some(strings(new_value)), None)
        } else if let Some(field) = text(query, "count_distinct") {
            ("cardinality", None, Some(vec![field.to_owned()].into()))
        } else if let Some(field) = text(query, "sum") {
            ("sum", Some(vec![field.to_owned()].into()), None)
        } else if let Some(field) = text(query, "max") {
            ("max", Some(vec![field.to_owned()].into()), None)
        } else {
            ("count", None, None)
        };
    out.insert("aggregation".into(), aggregation.into());
    out.insert("groupByFields".into(), strings(items(query, "group_by")));
    out.insert(
        "distinctFields".into(),
        distinct.unwrap_or_else(|| Json::Array(Vec::new())),
    );
    if let Some(metrics) = metrics {
        out.insert("metrics".into(), metrics);
    }
    if field(query, "keep_missing_groups").is_some_and(Json::is_true) {
        out.insert("hasOptionalGroupByFields".into(), Json::Bool(true));
    }
    Json::Object(out)
}

/// A case's `status`: its `severity`, else `response.alert_severity`'s, else
/// `info`.
pub fn case_status(rule: &Rule, case: &Json) -> String {
    if let Some(severity) = text(case, "severity") {
        return severity.to_owned();
    }
    rule.response()
        .and_then(|response| response.get("alert_severity"))
        .and_then(|severity| alert_severity(&deploy::text(severity).trim().to_lowercase()))
        .unwrap_or(DEFAULT_SEVERITY)
        .to_owned()
}

/// The handle a case's `notify` entry names on `tenant`: a raw `@handle` as
/// written; an alias through the tenant's `notifications`, or with no tenant
/// (a dry run) the placeholder `<tenant:notifications.ALIAS>`. An alias the
/// tenant does not define is `datadog_notification_alias`.
fn notification(entry: &str, tenant: Option<&Json>, uuid: &str) -> Result<String, CompileError> {
    if entry.starts_with('@') {
        return Ok(entry.to_owned());
    }
    let Some(tenant) = tenant else {
        return Ok(deploy::tenant_value(&format!("notifications.{entry}")));
    };
    deploy::setup(tenant, "notifications")
        .and_then(|aliases| aliases.get(entry))
        .and_then(Json::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            CompileError::new(
                NOTIFICATION_ALIAS,
                format!(
                    "{DISPLAY}: rule {uuid}: the notification alias {entry:?} is not defined on \
                     tenant {}",
                    deploy::tenant_name(tenant)
                ),
                Some(
                    "Add it to [tenants.setup.notifications] in platforms/datadog.toml, or write \
                     the Datadog @handle itself",
                ),
            )
        })
}

fn case(
    rule: &Rule,
    case: &Json,
    strategy: StatusStrategy,
    tenant: Option<&Json>,
) -> Result<Json, CompileError> {
    let mut out = Object::new();
    out.insert(
        "name".into(),
        field(case, "name")
            .map(deploy::text)
            .unwrap_or_default()
            .into(),
    );
    out.insert("status".into(), case_status(rule, case).into());
    if let Some(condition) = text(case, "condition") {
        out.insert("condition".into(), condition.trim().into());
    }
    let notifications = if strategy == StatusStrategy::Preview {
        Vec::new()
    } else {
        items(case, "notify")
            .iter()
            .map(|entry| notification(&deploy::text(entry), tenant, &rule.uuid).map(Json::Str))
            .collect::<Result<Vec<_>, _>>()?
    };
    out.insert("notifications".into(), Json::Array(notifications));
    Ok(Json::Object(out))
}

fn options(block: &Json) -> Result<Json, CompileError> {
    let detection = field(block, "detection");
    let signal = field(block, "signal");
    let method = method(block);
    let detection_text = |key: &str| detection.and_then(|detection| text(detection, key));
    let mut out = Object::new();
    out.insert("detectionMethod".into(), detection_method(method).into());
    let window = detection
        .and_then(|detection| window_text(detection, "window"))
        .unwrap_or(DEFAULT_WINDOW);
    out.insert(
        "evaluationWindow".into(),
        seconds(window, "detection.window")?,
    );
    let keep_alive = signal
        .and_then(|signal| window_text(signal, "keep_alive"))
        .unwrap_or(DEFAULT_KEEP_ALIVE);
    out.insert(
        "keepAlive".into(),
        seconds(keep_alive, "signal.keep_alive")?,
    );
    let max_duration = signal
        .and_then(|signal| window_text(signal, "max_duration"))
        .unwrap_or(DEFAULT_MAX_DURATION);
    out.insert(
        "maxSignalDuration".into(),
        seconds(max_duration, "signal.max_duration")?,
    );
    out.insert(
        "decreaseCriticalityBasedOnEnv".into(),
        Json::Bool(
            signal
                .and_then(|signal| field(signal, "downgrade_non_production"))
                .is_some_and(Json::is_true),
        ),
    );
    let day_count = |value: &str, low: i64, key: &str| {
        days(value, low)
            .map(Json::Int)
            .ok_or_else(|| failed(&format!("{key} {value:?} is not a number of days")))
    };
    match method {
        "new_value" => {
            let mut new_value = Object::new();
            let forget = detection_text("forget_after")
                .ok_or_else(|| failed("method: new_value needs detection.forget_after"))?;
            new_value.insert(
                "forgetAfter".into(),
                day_count(forget, 1, "detection.forget_after")?,
            );
            new_value.insert("learningMethod".into(), "duration".into());
            new_value.insert(
                "learningDuration".into(),
                day_count(
                    detection_text("learning").unwrap_or(DEFAULT_NEW_VALUE_LEARNING),
                    0,
                    "detection.learning",
                )?,
            );
            out.insert("newValueOptions".into(), Json::Object(new_value));
        }
        "anomaly" => {
            let mut anomaly = Object::new();
            if let Some(bucket) = detection_text("bucket") {
                anomaly.insert(
                    "bucketDuration".into(),
                    bucket_seconds(bucket).map(Json::Int).ok_or_else(|| {
                        failed(&format!("detection.bucket {bucket:?} is not a bucket"))
                    })?,
                );
            }
            if let Some(learning) = detection_text("learning") {
                anomaly.insert(
                    "learningDuration".into(),
                    anomaly_learning_hours(learning)
                        .map(Json::Int)
                        .ok_or_else(|| {
                            failed(&format!(
                                "detection.learning {learning:?} is not an anomaly learning \
                                 duration"
                            ))
                        })?,
                );
            }
            if let Some(tolerance) = detection.and_then(|detection| field(detection, "tolerance")) {
                anomaly.insert("detectionTolerance".into(), tolerance.clone());
            }
            out.insert("anomalyDetectionOptions".into(), Json::Object(anomaly));
        }
        "impossible_travel" => {
            let mut travel = Object::new();
            let learning = detection_text("learning");
            travel.insert(
                "baselineUserLocations".into(),
                Json::Bool(learning.is_some()),
            );
            if let Some(learning) = learning {
                travel.insert(
                    "baselineUserLocationsDuration".into(),
                    day_count(learning, 1, "detection.learning")?,
                );
            }
            if detection
                .and_then(|detection| field(detection, "detect_ip_transitions"))
                .is_some_and(Json::is_true)
            {
                travel.insert("detectIpTransition".into(), Json::Bool(true));
            }
            out.insert("impossibleTravelOptions".into(), Json::Object(travel));
        }
        _ => {}
    }
    Ok(Json::Object(out))
}

/// Markdown text with Datadog's template braces kept literal: a `{{` in a
/// description is not read as a template variable (RFC §7.3).
pub fn escape_template(text: &str) -> String {
    text.replace("{{", "{ {").replace("}}", "} }")
}

/// The query and its cases in words, for the derived message's Strategy.
fn strategy_text(block: &Json) -> String {
    let method = method(block);
    let mut lines = Vec::new();
    for (index, query) in items(block, "queries").iter().enumerate() {
        let name = text(query, "name").map_or_else(|| default_query_name(index), str::to_owned);
        let search = field(query, "query").map(deploy::text).unwrap_or_default();
        lines.push(format!(
            "- Query `{name}` searches {}: `{}`",
            text(query, "from").unwrap_or("logs"),
            escape_template(search.trim()).replace('`', "'")
        ));
    }
    let window = field(block, "detection")
        .and_then(|detection| window_text(detection, "window"))
        .unwrap_or(DEFAULT_WINDOW);
    lines.push(format!(
        "- Detection method: {method}, over a {window} window."
    ));
    for case in items(block, "cases") {
        let label = text(case, "name").unwrap_or("A case");
        match text(case, "condition") {
            Some(condition) => lines.push(format!(
                "- {}: `{}`",
                escape_template(label),
                escape_template(condition.trim())
            )),
            None => lines.push(format!("- {}.", escape_template(label))),
        }
    }
    lines.join("\n")
}

/// The message when the block has none (RFC §7.3): Goal, Strategy and Triage
/// and response, in the sections Datadog's own rules use.
pub fn derive_message(rule: &Rule, block: &Json) -> String {
    let mut sections = vec![format!(
        "## Goal\n{}",
        escape_template(rule.description().trim())
    )];
    sections.push(format!("## Strategy\n{}", strategy_text(block)));
    let procedure = rule
        .response()
        .and_then(|response| response.get("procedure"))
        .map(procedure_text)
        .filter(|text| !text.trim().is_empty());
    if let Some(procedure) = procedure {
        sections.push(format!(
            "## Triage and response\n{}",
            escape_template(procedure.trim())
        ));
    }
    sections.join("\n\n")
}

/// `response.procedure` as text: a string as it is, a table's values each on
/// a line.
fn procedure_text(procedure: &Json) -> String {
    match procedure {
        Json::Str(text) => text.clone(),
        Json::Object(fields) => fields
            .iter()
            .filter(|(_, value)| !value.is_null())
            .map(|(key, value)| format!("### {key}\n{}", deploy::text(value).trim()))
            .collect::<Vec<_>>()
            .join("\n\n"),
        other => deploy::text(other),
    }
}

/// A name in a tag: lower case, every run of other characters one `-`.
fn slug(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    out.trim_end_matches('-').to_owned()
}

/// The parent of a sub-technique (`T1110.001` → `T1110`).
fn parent_technique(id: &str) -> &str {
    id.split_once('.').map_or(id, |(parent, _)| parent)
}

/// The values of `source:` the queries name (`source:okta`), each once, in
/// order. A quoted or grouped value is left out: only a plain term names one
/// source.
pub fn sources(block: &Json) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for query in items(block, "queries") {
        let search = field(query, "query").map(deploy::text).unwrap_or_default();
        let mut previous: Option<char> = None;
        let mut rest = search.as_str();
        while let Some(at) = rest.find("source:") {
            let before = rest[..at].chars().next_back().or(previous);
            let starts_a_term =
                before.is_none_or(|ch| ch.is_whitespace() || matches!(ch, '(' | '+'));
            let after = &rest[at + "source:".len()..];
            let value: String = after
                .chars()
                .take_while(|ch| !ch.is_whitespace() && !matches!(ch, '(' | ')' | '"' | '\\'))
                .collect();
            let negated = rest[..at].ends_with('-')
                || rest[..at]
                    .trim_end()
                    .rsplit(|ch: char| ch.is_whitespace() || ch == '(')
                    .next()
                    == Some("NOT");
            if starts_a_term && !value.is_empty() && !value.contains(['*', '?']) && !negated {
                let value = value.to_lowercase();
                if !found.contains(&value) {
                    found.push(value);
                }
            }
            previous = Some(':');
            rest = after;
        }
    }
    found
}

/// The derived tags (RFC §7.4): `source:`, `tactic:`, `technique:`,
/// `security:attack` and `opentide_uuid:`, all lower case. Techniques come
/// from the rule and the objectives it inherits, sub-techniques as their
/// parents.
pub fn derived_tags(cx: &Context<'_>, rule: &Rule, block: &Json) -> Vec<String> {
    // A source Datadog would rewrite as a tag is left out: the tag the rule
    // holds would never equal the one compiled.
    let mut tags: Vec<String> = sources(block)
        .into_iter()
        .map(|source| format!("source:{source}"))
        .filter(|tag| tag_problem(tag).is_none())
        .collect();
    let mut techniques: Vec<String> = Vec::new();
    for id in rule_techniques(cx, rule) {
        let parent = parent_technique(&id).to_owned();
        if !techniques.contains(&parent) {
            techniques.push(parent);
        }
    }
    let mut tactics: Vec<(&str, &str)> = Vec::new();
    let mut technique_tags = Vec::new();
    for id in &techniques {
        let Some(name) = cx.attack.name(id) else {
            continue;
        };
        if attack::non_enterprise(name) {
            continue;
        }
        technique_tags.push(format!("technique:{}-{}", id.to_lowercase(), slug(name)));
        for stage in cx.attack.stages(id) {
            if let Some(tactic) = attack::tactic(&stage)
                && !tactics.contains(&tactic)
            {
                tactics.push(tactic);
            }
        }
    }
    tags.extend(
        attack::TACTIC_ORDER
            .iter()
            .filter(|tactic| tactics.contains(tactic))
            .map(|(name, id)| format!("tactic:{}-{}", id.to_lowercase(), slug(name))),
    );
    tags.extend(technique_tags);
    tags.push("security:attack".to_owned());
    tags.push(format!("{UUID_TAG}:{}", rule.uuid.to_lowercase()));
    tags
}

/// Every tag the body sends: the block's, the derived ones, the tenant's,
/// and under `PREVIEW` the preview tag, each once, in that order. A tenant
/// tag Datadog would refuse or rewrite fails the compile (`datadog_tag`).
fn tags(
    cx: &Context<'_>,
    rule: &Rule,
    block: &Json,
    strategy: StatusStrategy,
    tenant: Option<&Json>,
) -> Result<Vec<String>, CompileError> {
    let mut all: Vec<String> = items(block, "tags").iter().map(deploy::text).collect();
    // The block's tags are the model's to check, but a `[[modifiers]]` entry
    // rewrites them after validation: they are checked as sent.
    if let Some(problem) = all.iter().find_map(|tag| tag_problem(tag)) {
        return Err(CompileError::new(
            "datadog_tag",
            format!("{DISPLAY}: rule {}: tag {problem}", rule.uuid),
            Some("Fix the tag in the block's tags, or in the modifier that sets them"),
        ));
    }
    all.extend(derived_tags(cx, rule, block));
    if let Some(tenant) = tenant {
        for tag in deploy::strings(deploy::setup(tenant, "tags")) {
            if let Some(problem) = tag_problem(&tag) {
                return Err(CompileError::new(
                    "datadog_tag",
                    format!(
                        "{DISPLAY}: tenant {}: tag {problem}",
                        deploy::tenant_name(tenant)
                    ),
                    Some("Fix the tag in [tenants.setup] tags of platforms/datadog.toml"),
                ));
            }
            all.push(tag);
        }
    }
    if strategy == StatusStrategy::Preview {
        all.push(PREVIEW_TAG.to_owned());
    }
    let mut unique: Vec<String> = Vec::with_capacity(all.len());
    for tag in all {
        if !unique.contains(&tag) {
            unique.push(tag);
        }
    }
    Ok(unique)
}

/// The body of `rule` under `strategy` on `tenant` (none for a dry run,
/// which shows a notification alias as `<tenant:notifications.ALIAS>` and no
/// tenant tags), RFC §7.2.
pub fn compile_body(
    cx: &Context<'_>,
    rule: &Rule,
    strategy: StatusStrategy,
    tenant: Option<&Json>,
) -> Result<Json, CompileError> {
    let block = block_of(rule)?;
    let method = method(block);
    let mut body = Object::new();
    body.insert("name".into(), rule_name(&rule.name, block).into());
    body.insert("type".into(), RULE_TYPE.into());
    body.insert(
        "isEnabled".into(),
        Json::Bool(strategy != StatusStrategy::Disablement),
    );
    body.insert(
        "queries".into(),
        Json::Array(
            items(block, "queries")
                .iter()
                .enumerate()
                .map(|(index, entry)| query(index, entry, method))
                .collect(),
        ),
    );
    body.insert(
        "cases".into(),
        Json::Array(
            items(block, "cases")
                .iter()
                .map(|entry| case(rule, entry, strategy, tenant))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    );
    body.insert("options".into(), options(block)?);
    let signal = field(block, "signal");
    let group_signals = signal.map_or(&[][..], |signal| items(signal, "group_by"));
    if !group_signals.is_empty() {
        body.insert("groupSignalsBy".into(), strings(group_signals));
    }
    body.insert(
        "hasExtendedTitle".into(),
        Json::Bool(
            signal
                .and_then(|signal| field(signal, "group_in_notification_title"))
                .is_some_and(Json::is_true),
        ),
    );
    let message = text(block, "message").map_or_else(
        || derive_message(rule, block),
        |message| message.trim_end().to_owned(),
    );
    body.insert("message".into(), message.into());
    body.insert(
        "tags".into(),
        tags(cx, rule, block, strategy, tenant)?.into(),
    );
    Ok(Json::Object(body))
}

/// What `rule` deploys under `strategy` on `tenant`.
pub fn compile_rule(
    cx: &Context<'_>,
    rule: &Rule,
    strategy: StatusStrategy,
    tenant: Option<&Json>,
) -> Result<DatadogRule, CompileError> {
    let body = compile_body(cx, rule, strategy, tenant)?;
    let name = body
        .get("name")
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(DatadogRule {
        uuid: rule.uuid.clone(),
        name,
        body,
    })
}

/// The body `rule` deploys on `tenant` (none for a dry run), under its
/// block's status.
pub fn compile_deployment(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: Option<&Json>,
) -> Result<DatadogRule, CompileError> {
    let strategy = strategy(cx, rule)?;
    compile_rule(cx, rule, strategy, tenant)
}

fn request(method: &str, path: String, body: Json) -> Json {
    let mut out = Object::new();
    out.insert("method".into(), method.into());
    out.insert("path".into(), path.into());
    out.insert("body".into(), body);
    Json::Object(out)
}

/// The create call: `POST /security_monitoring/rules` with the body.
pub fn create_request(compiled: &DatadogRule) -> Json {
    request("POST", RULES_PATH.to_owned(), compiled.body.clone())
}

/// The validation call every create and update starts with.
pub fn validation_request(compiled: &DatadogRule) -> Json {
    request("POST", VALIDATION_PATH.to_owned(), compiled.body.clone())
}

/// The update body: the compiled body without `type`, which Datadog's update
/// payload does not take, and with the `version` the `GET` returned (RFC
/// §8.2). The connector also writes in the defaults Datadog holds for what
/// the body leaves out (`opentide_connectors::datadog::update_body`).
pub fn update_body(compiled: &DatadogRule, version: Json) -> Json {
    let mut body = match &compiled.body {
        Json::Object(fields) => fields.clone(),
        _ => Object::new(),
    };
    body.shift_remove("type");
    body.insert("version".into(), version);
    Json::Object(body)
}

/// The update call: `PUT /security_monitoring/rules/{id}`, with the
/// `version` the `GET` returned.
pub fn update_request(compiled: &DatadogRule, rule_id: &str, version: Json) -> Json {
    request(
        "PUT",
        format!("{RULES_PATH}/{rule_id}"),
        update_body(compiled, version),
    )
}

/// `at` as `YYYY-MM-DDThh:mm:ssZ`, in UTC.
pub fn utc(at: jiff::Timestamp) -> String {
    at.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// A `POST /logs/events/search` body (RFC §8.2): the query, the window,
/// the indexes and storage tier when given, and a page's size; `cursor`
/// continues a search.
pub fn search_body(
    query: &str,
    start: jiff::Timestamp,
    end: jiff::Timestamp,
    limit: usize,
    indexes: &[String],
    cursor: Option<&str>,
) -> Json {
    let mut filter = Object::new();
    filter.insert("query".into(), query.trim().into());
    filter.insert("from".into(), utc(start).into());
    filter.insert("to".into(), utc(end).into());
    if !indexes.is_empty() {
        filter.insert("indexes".into(), indexes.to_vec().into());
    }
    let mut page = Object::new();
    page.insert(
        "limit".into(),
        Json::Int(i64::try_from(limit.min(PAGE_LIMIT)).unwrap_or(1)),
    );
    if let Some(cursor) = cursor {
        page.insert("cursor".into(), cursor.into());
    }
    let mut body = Object::new();
    body.insert("filter".into(), Json::Object(filter));
    body.insert("page".into(), Json::Object(page));
    body.insert("sort".into(), "-timestamp".into());
    Json::Object(body)
}

/// The `--live` check of a search (profile `search`): one event over the
/// minute before `now`.
pub fn live_search_request(query: &str, now: jiff::Timestamp) -> Json {
    let start = now
        .checked_sub(jiff::SignedDuration::from_mins(LIVE_WINDOW_MINUTES))
        .unwrap_or(now);
    request(
        "POST",
        LOGS_SEARCH_PATH.to_owned(),
        search_body(query, start, now, 1, &[], None),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert_eq!(slug("Credential Access"), "credential-access");
        assert_eq!(slug("Brute Force"), "brute-force");
        assert_eq!(
            slug("Exploitation for Privilege Escalation"),
            "exploitation-for-privilege-escalation"
        );
        assert_eq!(
            slug("OS Credential Dumping: LSASS"),
            "os-credential-dumping-lsass"
        );
    }

    #[test]
    fn sources_are_the_plain_source_terms() {
        let block = |queries: &[&str]| {
            Json::Object(Object::from_iter([(
                "queries".to_owned(),
                Json::Array(
                    queries
                        .iter()
                        .map(|query| {
                            Json::Object(Object::from_iter([(
                                "query".to_owned(),
                                Json::Str((*query).to_owned()),
                            )]))
                        })
                        .collect(),
                ),
            )]))
        };
        assert_eq!(
            sources(&block(&[
                "source:okta @evt.outcome:FAILURE",
                "source:okta x"
            ])),
            vec!["okta"]
        );
        assert_eq!(
            sources(&block(&["(source:cloudtrail OR source:Okta) -source:gcp"])),
            vec!["cloudtrail", "okta"]
        );
        assert_eq!(
            sources(&block(&["source:web* @x:source:y", "source:(a OR b)"])),
            Vec::<String>::new()
        );
        assert_eq!(
            sources(&block(&["NOT source:gcp source:aws", "(NOT source:x)"])),
            vec!["aws"]
        );
    }

    #[test]
    fn templates_in_rule_text_are_escaped() {
        assert_eq!(escape_template("see {{x}}"), "see { {x} }");
    }

    #[test]
    fn a_sub_technique_is_its_parent() {
        assert_eq!(parent_technique("T1110.001"), "T1110");
        assert_eq!(parent_technique("T1078"), "T1078");
    }
}
