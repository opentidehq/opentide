//! Exabeam New-Scale SIEM (exabeam-1.0): an opentide rule's `exabeam` block
//! as a correlation rule body.
//!
//! The author writes the sequences and the response settings; the rest is
//! derived from the rule: the Exabeam rule name, the description (with the
//! ATT&CK line and the `opentide:` marker) and the severity. The body of
//! `POST /correlation-rules/v2/rules` (create) and `PUT
//! /correlation-rules/v2/rules/{id}` (update) is the same, and every update
//! sends all of it: `PUT` replaces the rule. Keys are built in the order of
//! the specification's Compiled body table; `tests/fixtures/exabeam/` holds
//! the bodies.

use opentide_schema::objects::platform::ExabeamConfig;
use opentide_schema::objects::platform::exabeam::{
    ExabeamDays, ExabeamEvery, ExabeamOutcome, ExabeamRecurrence, ExabeamSequence, ExabeamValue,
    ExabeamValueItem, delay_minutes, duration, unit_name,
};

use crate::elastic::rule_techniques;
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;
use crate::{Context, typed};

/// The platform's identifier.
pub const PLATFORM: &str = "exabeam";
/// The platform's name in messages.
pub const DISPLAY: &str = "Exabeam New-Scale SIEM";
/// The correlation rules endpoint.
pub const RULES_PATH: &str = "/correlation-rules/v2/rules";
/// The Search endpoint.
pub const SEARCH_PATH: &str = "/search/v2/events";
/// The severity when neither the block nor `response.alert_severity` names one.
pub const DEFAULT_SEVERITY: &str = "medium";
/// The window `validate query --live` searches: the console's "Test Last 15 mins".
pub const LIVE_WINDOW_MINUTES: i64 = 15;

/// `response.alert_severity` → Exabeam `severity` (exabeam-1.0, Severity).
fn alert_severity(name: &str) -> Option<&'static str> {
    match name {
        "critical" => Some("critical"),
        "high" => Some("high"),
        "medium" => Some("medium"),
        "low" => Some("low"),
        "informational" => Some("none"),
        _ => None,
    }
}

/// `schedule[].every` → `recurrenceType`.
fn recurrence_type(every: &str) -> Option<&'static str> {
    match every {
        "day" => Some("DAILY"),
        "week" => Some("WEEKLY"),
        "month" => Some("MONTHLY"),
        "days" => Some("CUSTOM"),
        _ => None,
    }
}

/// What a block deploys on one tenant, after derivation (`ExabeamRule`).
#[derive(Debug, Clone, PartialEq)]
pub struct ExabeamRule {
    /// The opentide rule's UUID.
    pub uuid: String,
    /// The Exabeam rule name.
    pub name: String,
    /// The create and update body.
    pub body: Json,
}

impl ExabeamRule {
    /// Whether the body sets a schedule.
    pub fn has_schedule(&self) -> bool {
        self.body.get("scheduleConfig").is_some()
    }
}

/// A text the block sets, unless empty.
fn filled(text: Option<&str>) -> Option<&str> {
    text.filter(|text| !text.is_empty())
}

/// The rule's Exabeam block, or the error naming the rule (`block_of`).
fn block_of(rule: &Rule) -> Result<&Json, CompileError> {
    rule.block(PLATFORM).ok_or_else(|| {
        CompileError::failed(
            DISPLAY,
            &format!("Rule {} ({}) has no exabeam block", rule.uuid, rule.name),
        )
    })
}

/// The rule's Exabeam block read by the model `validate` checks it with
/// (`ExabeamConfig`, #1951; [`typed::read_block`]), or the error naming the
/// rule or the fields whose shape the model refuses.
fn config_of(rule: &Rule) -> Result<ExabeamConfig, CompileError> {
    typed::read_block(block_of(rule)?, PLATFORM, DISPLAY)
}

/// The strategy `block`'s status maps to.
fn status_strategy(
    cx: &Context<'_>,
    block: &ExabeamConfig,
) -> Result<StatusStrategy, CompileError> {
    cx.statuses
        .strategy(&block.status)
        .map_err(|error| CompileError::failed(DISPLAY, &error.to_string()))
}

/// The strategy the block's status maps to.
pub fn strategy(cx: &Context<'_>, rule: &Rule) -> Result<StatusStrategy, CompileError> {
    status_strategy(cx, &config_of(rule)?)
}

/// The shared `name`, else the opentide rule `name` (`exabeam_name`).
pub fn exabeam_name<'a>(rule_name: &'a str, block_name: Option<&'a str>) -> &'a str {
    block_name
        .filter(|name| !name.is_empty())
        .unwrap_or(rule_name)
}

/// The description, whitespace collapsed; the ATT&CK line; the `opentide:`
/// marker (`derive_description`).
pub fn derive_description(cx: &Context<'_>, rule: &Rule) -> String {
    let text = rule
        .description()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let techniques = rule_techniques(cx, rule);
    let mut lines = Vec::new();
    if !techniques.is_empty() {
        lines.push(format!("ATT&CK: {}", techniques.join(", ")));
    }
    lines.push(format!("opentide: {}", rule.uuid));
    format!("{text}\n\n{}", lines.join("\n"))
}

/// The block `severity`, else `response.alert_severity`'s, else `medium`
/// (`derive_severity`).
pub fn derive_severity(rule: &Rule, block: &ExabeamConfig) -> String {
    if let Some(severity) = block.severity {
        return severity.as_str().to_owned();
    }
    let Some(severity) = rule
        .response()
        .and_then(|response| response.get("alert_severity"))
    else {
        return DEFAULT_SEVERITY.to_owned();
    };
    alert_severity(&Json::to_text(severity).trim().to_lowercase())
        .unwrap_or(DEFAULT_SEVERITY)
        .to_owned()
}

/// `(time, unit)` of a duration, the unit spelled as Exabeam takes it
/// (`time_unit`).
pub fn time_unit(value: &Json, units: &str) -> Result<(Json, &'static str), CompileError> {
    let parsed = value.as_str().and_then(|text| duration(text, units));
    match parsed {
        Some((number, unit)) if i64::try_from(number).is_ok() => Ok((
            Json::Int(i64::try_from(number).unwrap_or(i64::MAX)),
            unit_name(unit),
        )),
        _ => Err(CompileError::failed(
            DISPLAY,
            &format!("{} is not a duration in {units}", value.to_compact()),
        )),
    }
}

/// [`time_unit`] of a duration the block writes.
fn window(text: &str, units: &str) -> Result<(Json, &'static str), CompileError> {
    time_unit(&Json::Str(text.to_owned()), units)
}

/// `value` as the API takes it: a number in its shortest form, a list joined
/// by `,` (`threshold_value`).
pub fn threshold_value(value: Option<&Json>) -> String {
    fn one(item: &Json) -> String {
        match item {
            Json::Float(float) if float.fract() == 0.0 && float.is_finite() => {
                format!("{float:.0}")
            }
            other => Json::to_text(other),
        }
    }
    match value {
        None | Some(Json::Null) => String::new(),
        Some(Json::Array(items)) => items.iter().map(one).collect::<Vec<_>>().join(","),
        Some(other) => one(other),
    }
}

/// A threshold's `value` as the block writes it.
fn value_json(value: &ExabeamValue) -> Json {
    match value {
        ExabeamValue::Int(integer) => Json::Int(*integer),
        ExabeamValue::Float(float) => Json::Float(*float),
        ExabeamValue::List(items) => Json::Array(
            items
                .iter()
                .map(|item| match item {
                    ExabeamValueItem::Text(text) => Json::Str(text.clone()),
                    ExabeamValueItem::Int(integer) => Json::Int(*integer),
                    ExabeamValueItem::Float(float) => Json::Float(*float),
                })
                .collect(),
        ),
    }
}

fn strings(values: Option<&Vec<String>>) -> Json {
    Json::Array(
        values
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|value| value.as_str().into())
            .collect(),
    )
}

/// Whether a list the block may set has items.
fn has_items(values: Option<&Vec<String>>) -> bool {
    values.is_some_and(|values| !values.is_empty())
}

fn condition(sequence: &ExabeamSequence) -> Result<Object, CompileError> {
    let group_by = sequence.group_by.as_ref();
    let threshold = sequence.threshold.as_ref();
    let mut condition = Object::new();
    condition.insert("triggerOnAnyMatch".into(), Json::Bool(threshold.is_none()));
    condition.insert("groupByOption".into(), Json::Bool(has_items(group_by)));
    condition.insert("groupBy".into(), strings(group_by));
    let Some(threshold) = threshold else {
        return Ok(condition);
    };
    condition.insert("functionType".into(), threshold.function.as_str().into());
    let column = filled(threshold.field.as_deref());
    condition.insert(
        "subject".into(),
        if column.is_some() { "field" } else { "event" }.into(),
    );
    if let Some(column) = column {
        condition.insert("field".into(), column.into());
    }
    condition.insert("operator".into(), threshold.operator.as_str().into());
    let value = threshold.value.as_ref().map(value_json);
    condition.insert("value".into(), threshold_value(value.as_ref()).into());
    let (time, unit) = window(&threshold.within, "mhd")?;
    condition.insert("time".into(), time);
    condition.insert("unit".into(), unit.into());
    Ok(condition)
}

fn sequence(sequence: &ExabeamSequence) -> Result<Json, CompileError> {
    let mut entry = Object::new();
    if let Some(name) = filled(sequence.name.as_deref()) {
        entry.insert("name".into(), name.into());
    }
    entry.insert("query".into(), sequence.query.trim().into());
    entry.insert("condition".into(), Json::Object(condition(sequence)?));
    Ok(Json::Object(entry))
}

fn outcomes(block: &ExabeamConfig, name: &str) -> Json {
    let outcome = block.outcome.map_or("alert", ExabeamOutcome::as_str);
    let email = block.email.as_ref();
    let mut outcomes = Object::new();
    outcomes.insert("sendAlertTriage".into(), Json::Bool(outcome == "alert"));
    outcomes.insert("createCase".into(), Json::Bool(outcome == "case"));
    outcomes.insert("sendEmail".into(), Json::Bool(email.is_some()));
    if outcome == "alert" {
        let mut triage = Object::new();
        triage.insert("name".into(), name.into());
        outcomes.insert("alertTriage".into(), Json::Object(triage));
    }
    if outcome == "case" {
        let mut case = Object::new();
        case.insert("description".into(), name.into());
        outcomes.insert("case".into(), Json::Object(case));
    }
    if let Some(email) = email {
        let mut out = Object::new();
        out.insert("recipients".into(), strings(Some(&email.recipients)));
        out.insert(
            "subject".into(),
            filled(email.subject.as_deref()).unwrap_or(name).into(),
        );
        out.insert(
            "attachCsv".into(),
            Json::Bool(email.attach_csv == Some(true)),
        );
        outcomes.insert("email".into(), Json::Object(out));
    }
    Json::Object(outcomes)
}

fn recurrence(recurrence: &ExabeamRecurrence) -> Json {
    let every = recurrence.every.as_str();
    let mut out = Object::new();
    out.insert(
        "recurrenceType".into(),
        recurrence_type(every).unwrap_or_default().into(),
    );
    out.insert("startTime".into(), recurrence.from_.as_str().into());
    out.insert("endTime".into(), recurrence.to.as_str().into());
    let upper = |day: Option<&String>| day.map_or("null", String::as_str).to_uppercase();
    // The days as the block writes them: weekday names, or day numbers.
    let days: Vec<Json> = match &recurrence.days {
        None => Vec::new(),
        Some(ExabeamDays::Names(names)) => names.iter().map(|name| name.as_str().into()).collect(),
        Some(ExabeamDays::Numbers(numbers)) => numbers.iter().copied().map(Json::Int).collect(),
    };
    match recurrence.every {
        ExabeamEvery::Week => {
            out.insert(
                "daysOfWeek".into(),
                Json::Array(
                    days.iter()
                        .map(|day| Json::to_text(day).to_uppercase().into())
                        .collect(),
                ),
            );
        }
        ExabeamEvery::Month => {
            out.insert("daysInMonth".into(), Json::Array(days));
            out.insert(
                "lastDayOfMonth".into(),
                Json::Bool(recurrence.last_day == Some(true)),
            );
        }
        ExabeamEvery::Days => {
            out.insert("dayFrom".into(), upper(recurrence.first.as_ref()).into());
            out.insert("dayTo".into(), upper(recurrence.last.as_ref()).into());
        }
        ExabeamEvery::Day => {}
    }
    Json::Object(out)
}

/// The create and update body of `rule` under `strategy` (`compile_body`,
/// exabeam-1.0, Compiled body). `tenant_test_mode` is the tenant's
/// `test_mode`, the default of a block that does not set one.
pub fn compile_body(
    cx: &Context<'_>,
    rule: &Rule,
    strategy: StatusStrategy,
    tenant_test_mode: bool,
) -> Result<Json, CompileError> {
    body(cx, rule, &config_of(rule)?, strategy, tenant_test_mode)
}

/// [`compile_body`] of the rule's block, read.
fn body(
    cx: &Context<'_>,
    rule: &Rule,
    block: &ExabeamConfig,
    strategy: StatusStrategy,
    tenant_test_mode: bool,
) -> Result<Json, CompileError> {
    let name = exabeam_name(&rule.name, Some(&block.name)).to_owned();
    let sequences = block
        .sequences
        .iter()
        .map(sequence)
        .collect::<Result<Vec<_>, _>>()?;
    let count = sequences.len();
    let mut sequences_config = Object::new();
    sequences_config.insert("sequences".into(), Json::Array(sequences));
    if count >= 2 {
        let Some(correlation) = &block.correlation else {
            return Err(CompileError::failed(
                DISPLAY,
                &format!("Rule {}: two or more sequences need correlation", rule.uuid),
            ));
        };
        let (time, unit) = window(&correlation.within, "mhd")?;
        let mut common = Object::new();
        common.insert("groupBy".into(), strings(correlation.group_by.as_ref()));
        common.insert("time".into(), time);
        common.insert("unit".into(), unit.into());
        sequences_config.insert("commonProperties".into(), Json::Object(common));
    }
    sequences_config.insert("outcomes".into(), outcomes(block, &name));
    let test_mode = block.test_mode.unwrap_or(tenant_test_mode);
    let mut body = Object::new();
    body.insert("name".into(), name.clone().into());
    body.insert("description".into(), derive_description(cx, rule).into());
    body.insert("severity".into(), derive_severity(rule, block).into());
    body.insert(
        "enabled".into(),
        Json::Bool(strategy != StatusStrategy::Disablement),
    );
    body.insert("testMode".into(), Json::Bool(test_mode));
    body.insert("sequencesConfig".into(), Json::Object(sequences_config));
    let mut suppress = Object::new();
    match &block.suppression {
        Some(suppression) => {
            let (time, unit) = window(&suppression.for_, "mhdw")?;
            suppress.insert("suppressOption".into(), Json::Bool(true));
            suppress.insert("suppressTime".into(), time);
            suppress.insert("suppressUnit".into(), unit.into());
            let group_by = suppression.group_by.as_ref();
            if has_items(group_by) {
                suppress.insert("granularSuppressOption".into(), Json::Bool(true));
                suppress.insert("suppressGroupFields".into(), strings(group_by));
            }
        }
        None => {
            suppress.insert("suppressOption".into(), Json::Bool(false));
        }
    }
    body.insert("suppressConfig".into(), Json::Object(suppress));
    let minutes = filled(block.delay.as_deref())
        .and_then(delay_minutes)
        .filter(|m| *m > 0);
    let mut delay = Object::new();
    match minutes {
        Some(minutes) => {
            delay.insert("delay".into(), Json::Bool(true));
            delay.insert(
                "delayTimeInMinutes".into(),
                Json::Int(i64::try_from(minutes).unwrap_or(i64::MAX)),
            );
        }
        None => {
            delay.insert("delay".into(), Json::Bool(false));
        }
    }
    body.insert("delayConfig".into(), Json::Object(delay));
    let schedule = block.schedule.as_deref().unwrap_or_default();
    if !schedule.is_empty() {
        let mut config = Object::new();
        config.insert(
            "recurrences".into(),
            Json::Array(schedule.iter().map(recurrence).collect()),
        );
        body.insert("scheduleConfig".into(), Json::Object(config));
    }
    Ok(Json::Object(body))
}

/// The tenant's `setup.test_mode` (a tenant table as the planner holds it).
pub fn tenant_test_mode(tenant: Option<&Json>) -> bool {
    tenant
        .and_then(|tenant| tenant.get("setup"))
        .and_then(|setup| setup.get("test_mode"))
        .is_some_and(Json::is_true)
}

/// What `rule` deploys under `strategy` on the tenant whose table is given
/// (`compile_rule`). Without a tenant (an offline preview), `testMode` is
/// `false` unless the block sets it.
pub fn compile_rule(
    cx: &Context<'_>,
    rule: &Rule,
    strategy: StatusStrategy,
    tenant: Option<&Json>,
) -> Result<ExabeamRule, CompileError> {
    exabeam_rule(cx, rule, &config_of(rule)?, strategy, tenant)
}

/// [`compile_rule`] of the rule's block, read.
fn exabeam_rule(
    cx: &Context<'_>,
    rule: &Rule,
    block: &ExabeamConfig,
    strategy: StatusStrategy,
    tenant: Option<&Json>,
) -> Result<ExabeamRule, CompileError> {
    let body = body(cx, rule, block, strategy, tenant_test_mode(tenant))?;
    let name = body
        .get("name")
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(ExabeamRule {
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
) -> Result<ExabeamRule, CompileError> {
    let block = config_of(rule)?;
    let strategy = status_strategy(cx, &block)?;
    exabeam_rule(cx, rule, &block, strategy, tenant)
}

fn request(method: &str, path: String, body: Json) -> Json {
    let mut out = Object::new();
    out.insert("method".into(), method.into());
    out.insert("path".into(), path.into());
    out.insert("body".into(), body);
    Json::Object(out)
}

/// The create call: method, path and body (`create_request`).
pub fn create_request(compiled: &ExabeamRule) -> Json {
    request("POST", RULES_PATH.to_owned(), compiled.body.clone())
}

/// The update call: `PUT` with the whole body (`update_request`).
pub fn update_request(compiled: &ExabeamRule, rule_id: &str) -> Json {
    request(
        "PUT",
        format!("{RULES_PATH}/{rule_id}"),
        compiled.body.clone(),
    )
}

/// `at` as `YYYY-MM-DDThh:mm:ssZ`, in UTC.
pub fn utc(at: jiff::Timestamp) -> String {
    at.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// A `POST /search/v2/events` body: the query as `filter`, every field
/// unless named (`search_body`).
pub fn search_body(
    query: &str,
    start: jiff::Timestamp,
    end: jiff::Timestamp,
    limit: usize,
    fields: &[String],
) -> Json {
    let mut body = Object::new();
    body.insert("filter".into(), query.trim().into());
    body.insert(
        "fields".into(),
        if fields.is_empty() {
            vec!["*".to_owned()].into()
        } else {
            fields.to_vec().into()
        },
    );
    body.insert("startTime".into(), utc(start).into());
    body.insert("endTime".into(), utc(end).into());
    body.insert(
        "limit".into(),
        Json::Int(i64::try_from(limit).unwrap_or(i64::MAX)),
    );
    Json::Object(body)
}

/// The `--live` filter check: one row over the 15 minutes before `now`
/// (`live_search_request`).
pub fn live_search_request(query: &str, now: jiff::Timestamp) -> Json {
    let start = now
        .checked_sub(jiff::SignedDuration::from_mins(LIVE_WINDOW_MINUTES))
        .unwrap_or(now);
    request(
        "POST",
        SEARCH_PATH.to_owned(),
        search_body(query, start, now, 1, &[]),
    )
}
