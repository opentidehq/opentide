//! Exabeam New-Scale SIEM (exabeam-1.0): an opentide rule's `exabeam` block
//! as a correlation rule body, a port of 0.28.0's
//! `platforms/exabeam/compile.py`.
//!
//! The author writes the sequences and the response settings; the rest is
//! derived from the rule: the Exabeam rule name, the description (with the
//! ATT&CK line and the `opentide:` marker) and the severity. The body of
//! `POST /correlation-rules/v2/rules` (create) and `PUT
//! /correlation-rules/v2/rules/{id}` (update) is the same, and every update
//! sends all of it: `PUT` replaces the rule. Keys are built in the order of
//! the specification's Compiled body table; `tests/fixtures/exabeam/` holds
//! the bodies.

use opentide_schema::objects::platform::exabeam::{delay_minutes, duration, unit_name};
use opentide_schema::objects::platform::python_strip;

use crate::Context;
use crate::elastic::rule_techniques;
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;

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

/// A key of a block table, a null read as the key left out.
fn field<'j>(table: &'j Json, key: &str) -> Option<&'j Json> {
    table.get(key).filter(|value| !value.is_null())
}

/// A string field that is set and not empty (Python's `if value:`).
fn text<'j>(table: &'j Json, key: &str) -> Option<&'j str> {
    field(table, key)
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
}

/// A list field's items, or none.
fn items<'j>(table: &'j Json, key: &str) -> &'j [Json] {
    match field(table, key) {
        Some(Json::Array(items)) => items,
        _ => &[],
    }
}

/// Python's `str()` of a scalar.
fn py_str(value: &Json) -> String {
    match value {
        Json::Null => "None".to_owned(),
        Json::Bool(true) => "True".to_owned(),
        Json::Bool(false) => "False".to_owned(),
        Json::Int(integer) => integer.to_string(),
        Json::Str(text) => text.clone(),
        other => other.to_compact(),
    }
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

/// The strategy the block's status maps to (`_strategy`).
pub fn strategy(cx: &Context<'_>, rule: &Rule) -> Result<StatusStrategy, CompileError> {
    let status = block_of(rule)?
        .get("status")
        .map_or_else(|| "None".to_owned(), py_str);
    cx.statuses
        .strategy(&status)
        .map_err(|error| CompileError::failed(DISPLAY, &error.exception_text()))
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
        .split(opentide_schema::objects::platform::is_python_space)
        .filter(|word| !word.is_empty())
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
pub fn derive_severity(rule: &Rule, block: &Json) -> String {
    if let Some(severity) = text(block, "severity") {
        return severity.to_owned();
    }
    let Some(severity) = rule
        .response()
        .and_then(|response| response.get("alert_severity"))
    else {
        return DEFAULT_SEVERITY.to_owned();
    };
    alert_severity(&python_strip(&py_str(severity)).to_lowercase())
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

/// `value` as the API takes it: a number in its shortest form, a list joined
/// by `,` (`threshold_value`).
pub fn threshold_value(value: Option<&Json>) -> String {
    fn one(item: &Json) -> String {
        match item {
            Json::Float(float) if float.fract() == 0.0 && float.is_finite() => {
                format!("{float:.0}")
            }
            other => py_str(other),
        }
    }
    match value {
        None | Some(Json::Null) => String::new(),
        Some(Json::Array(items)) => items.iter().map(one).collect::<Vec<_>>().join(","),
        Some(other) => one(other),
    }
}

fn strings(values: &[Json]) -> Json {
    Json::Array(values.iter().map(|value| py_str(value).into()).collect())
}

fn condition(sequence: &Json) -> Result<Object, CompileError> {
    let group_by = items(sequence, "group_by");
    let threshold = field(sequence, "threshold");
    let mut condition = Object::new();
    condition.insert("triggerOnAnyMatch".into(), Json::Bool(threshold.is_none()));
    condition.insert("groupByOption".into(), Json::Bool(!group_by.is_empty()));
    condition.insert("groupBy".into(), strings(group_by));
    let Some(threshold) = threshold else {
        return Ok(condition);
    };
    let function = field(threshold, "function").map(py_str).unwrap_or_default();
    condition.insert("functionType".into(), function.into());
    let column = text(threshold, "field");
    condition.insert(
        "subject".into(),
        if column.is_some() { "field" } else { "event" }.into(),
    );
    if let Some(column) = column {
        condition.insert("field".into(), column.into());
    }
    let operator = field(threshold, "operator").map(py_str).unwrap_or_default();
    condition.insert("operator".into(), operator.into());
    condition.insert(
        "value".into(),
        threshold_value(field(threshold, "value")).into(),
    );
    let (time, unit) = time_unit(threshold.get("within").unwrap_or(&Json::Null), "mhd")?;
    condition.insert("time".into(), time);
    condition.insert("unit".into(), unit.into());
    Ok(condition)
}

fn sequence(sequence: &Json) -> Result<Json, CompileError> {
    let mut entry = Object::new();
    if let Some(name) = text(sequence, "name") {
        entry.insert("name".into(), name.into());
    }
    let query = field(sequence, "query").map(py_str).unwrap_or_default();
    entry.insert("query".into(), python_strip(&query).into());
    entry.insert("condition".into(), Json::Object(condition(sequence)?));
    Ok(Json::Object(entry))
}

fn outcomes(block: &Json, name: &str) -> Json {
    let outcome = text(block, "outcome").unwrap_or("alert");
    let email = field(block, "email");
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
        out.insert("recipients".into(), strings(items(email, "recipients")));
        out.insert(
            "subject".into(),
            text(email, "subject").unwrap_or(name).into(),
        );
        out.insert(
            "attachCsv".into(),
            Json::Bool(field(email, "attach_csv").is_some_and(Json::truthy)),
        );
        outcomes.insert("email".into(), Json::Object(out));
    }
    Json::Object(outcomes)
}

fn recurrence(recurrence: &Json) -> Result<Json, CompileError> {
    let every = text(recurrence, "every").unwrap_or_default();
    let Some(kind) = recurrence_type(every) else {
        return Err(CompileError::failed(
            DISPLAY,
            &format!("'{every}' is not a recurrence"),
        ));
    };
    let mut out = Object::new();
    out.insert("recurrenceType".into(), kind.into());
    out.insert(
        "startTime".into(),
        field(recurrence, "from")
            .map(py_str)
            .unwrap_or_default()
            .into(),
    );
    out.insert(
        "endTime".into(),
        field(recurrence, "to")
            .map(py_str)
            .unwrap_or_default()
            .into(),
    );
    let upper = |key: &str| {
        field(recurrence, key)
            .map(py_str)
            .unwrap_or_else(|| "None".to_owned())
            .to_uppercase()
    };
    match every {
        "week" => {
            out.insert(
                "daysOfWeek".into(),
                Json::Array(
                    items(recurrence, "days")
                        .iter()
                        .map(|day| py_str(day).to_uppercase().into())
                        .collect(),
                ),
            );
        }
        "month" => {
            out.insert(
                "daysInMonth".into(),
                Json::Array(items(recurrence, "days").to_vec()),
            );
            out.insert(
                "lastDayOfMonth".into(),
                Json::Bool(field(recurrence, "last_day").is_some_and(Json::truthy)),
            );
        }
        "days" => {
            out.insert("dayFrom".into(), upper("first").into());
            out.insert("dayTo".into(), upper("last").into());
        }
        _ => {}
    }
    Ok(Json::Object(out))
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
    let block = block_of(rule)?;
    let name = exabeam_name(&rule.name, text(block, "name")).to_owned();
    let sequences = items(block, "sequences")
        .iter()
        .map(sequence)
        .collect::<Result<Vec<_>, _>>()?;
    let count = sequences.len();
    let mut sequences_config = Object::new();
    sequences_config.insert("sequences".into(), Json::Array(sequences));
    if count >= 2 {
        let Some(correlation) = field(block, "correlation") else {
            return Err(CompileError::failed(
                DISPLAY,
                &format!("Rule {}: two or more sequences need correlation", rule.uuid),
            ));
        };
        let (time, unit) = time_unit(correlation.get("within").unwrap_or(&Json::Null), "mhd")?;
        let mut common = Object::new();
        common.insert("groupBy".into(), strings(items(correlation, "group_by")));
        common.insert("time".into(), time);
        common.insert("unit".into(), unit.into());
        sequences_config.insert("commonProperties".into(), Json::Object(common));
    }
    sequences_config.insert("outcomes".into(), outcomes(block, &name));
    let test_mode = match field(block, "test_mode") {
        Some(flag) => flag.truthy(),
        None => tenant_test_mode,
    };
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
    match field(block, "suppression") {
        Some(suppression) => {
            let (time, unit) = time_unit(suppression.get("for").unwrap_or(&Json::Null), "mhdw")?;
            suppress.insert("suppressOption".into(), Json::Bool(true));
            suppress.insert("suppressTime".into(), time);
            suppress.insert("suppressUnit".into(), unit.into());
            let group_by = items(suppression, "group_by");
            if !group_by.is_empty() {
                suppress.insert("granularSuppressOption".into(), Json::Bool(true));
                suppress.insert("suppressGroupFields".into(), strings(group_by));
            }
        }
        None => {
            suppress.insert("suppressOption".into(), Json::Bool(false));
        }
    }
    body.insert("suppressConfig".into(), Json::Object(suppress));
    let minutes = text(block, "delay")
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
    let schedule = items(block, "schedule");
    if !schedule.is_empty() {
        let mut config = Object::new();
        config.insert(
            "recurrences".into(),
            Json::Array(
                schedule
                    .iter()
                    .map(recurrence)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
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
        .is_some_and(Json::truthy)
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
    let body = compile_body(cx, rule, strategy, tenant_test_mode(tenant))?;
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

/// `at` as `YYYY-MM-DDThh:mm:ssZ`, in UTC (`_utc`).
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
    body.insert("filter".into(), python_strip(query).into());
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
