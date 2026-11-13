//! Splunk: the saved search a deploy writes on one tenant
//! (`platforms/splunk/deployer.py` `config_mdr`, `_apply_flat_modifiers`,
//! `_build_actions_config`, `_apply_saved_search`; `client.py`
//! `create_query`, `cron_to_timeframe`, `splunk_timerange`).
//!
//! The Splunk client builds the URLs: a write's `url` is the REST path under the
//! tenant's app namespace (`saved/searches`). The saved search is created
//! (it is not there yet), then updated with its settings, then with the
//! settings Splunk takes only once the others are set (`alert.suppress`,
//! `is_scheduled`, `actions`, `search`).

use crate::Context;
use crate::deploy::{self, Write};
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;

/// The platform's key under `configurations`.
pub const PLATFORM: &str = "splunk";

/// The platform's display name, in messages.
pub const DISPLAY: &str = "Splunk";

/// The minute and hour a frequency schedule runs at: drawn at random
/// (`frequency_scheduling = "random"`, the client's `randrange`) or the
/// clock's (`"current"`), as the caller reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// The random minute (0 to 59) and hour (0 to 23).
    pub random: (u32, u32),
    /// The current UTC minute and hour.
    pub now: (u32, u32),
}

/// The frequency mode (`correct_timerange_mode`): unset is `random`, an
/// unknown value `current`.
fn timerange_mode(value: Option<&Json>) -> &str {
    match value.filter(|value| value.truthy()) {
        None => "random",
        Some(Json::Str(mode)) if matches!(mode.as_str(), "random" | "current" | "custom") => mode,
        Some(_) => "current",
    }
}

/// Python's `int()` of a count.
fn count(text: &str) -> Option<i64> {
    text.trim().parse().ok()
}

fn invalid(message: &str) -> CompileError {
    CompileError::failed(DISPLAY, message)
}

/// The cron of a frequency (`cron_to_timeframe`): `15m`, `2h` or `1d`.
pub fn cron_to_timeframe(
    frequency: &str,
    mode: &str,
    custom_time: Option<&str>,
    clock: Clock,
) -> Result<String, CompileError> {
    let mut chars = frequency.chars();
    let unit = chars.next_back();
    let count = count(chars.as_str()).ok_or_else(|| {
        invalid(&format!(
            "invalid literal for int() with base 10: {}",
            crate::strategy::python_repr(chars.as_str())
        ))
    })?;
    let (minute, hour) = match mode {
        "random" => (clock.random.0.to_string(), clock.random.1.to_string()),
        "current" => (format!("{:02}", clock.now.0), format!("{:02}", clock.now.1)),
        _ => {
            let Some(custom) = custom_time.filter(|custom| !custom.is_empty()) else {
                return Err(invalid(
                    "When selecting a custom time, you need to input a time in the correct \
                     format: HHhmm.",
                ));
            };
            let parts: Vec<&str> = custom.split('h').collect();
            let [hour, minute] = parts.as_slice() else {
                return Err(invalid(&format!(
                    "custom_time {} is not HHhmm",
                    crate::strategy::python_repr(custom)
                )));
            };
            ((*minute).to_owned(), (*hour).to_owned())
        }
    };
    Ok(match unit {
        Some('m') => format!("*/{count} * * * *"),
        Some('h') => format!("{minute} */{count} * * *"),
        Some('d') => format!("{minute} {hour} */{count} * *"),
        _ => {
            return Err(invalid(
                "Time unit not supported by the crontab converter (expects m, h or d)",
            ));
        }
    })
}

/// The earliest time of a lookback (`splunk_timerange`): `-<minutes>m@m`,
/// the minutes stretched by `skew` (0.1 for 10 %) and moved by `offset`,
/// rounded half to even as Python's `round`.
pub fn splunk_timerange(time: &str, skew: f64, offset: i64) -> Result<String, CompileError> {
    let mut chars = time.chars();
    let unit = chars.next_back();
    let count = count(chars.as_str()).ok_or_else(|| {
        invalid(&format!(
            "invalid literal for int() with base 10: {}",
            crate::strategy::python_repr(chars.as_str())
        ))
    })?;
    let minutes = match unit {
        Some('h') => count * 60,
        Some('d') => count * 1440,
        Some('m') => count,
        _ => {
            return Err(invalid(
                "Time unit not supported by the Splunk earliest-time converter (expects m, h or d)",
            ));
        }
    };
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        reason = "a lookback in minutes is far inside f64's exact integers"
    )]
    let stretched = (minutes as f64 * (skew + 1.0)).round_ties_even() as i64;
    Ok(format!("-{}m@m", offset + stretched))
}

/// The tenant's settings (`use_tenant`).
struct Settings {
    actions: Vec<String>,
    default_actions: Vec<String>,
    mode: String,
    skew: f64,
    offset: i64,
    enterprise_security: bool,
}

fn strings(value: Option<&Json>) -> Vec<String> {
    match value {
        Some(Json::Array(items)) => items.iter().map(deploy::text).collect(),
        _ => Vec::new(),
    }
}

fn settings(tenant: &Json) -> Result<Settings, CompileError> {
    let skew = match deploy::setup(tenant, "allow_skew").filter(|value| value.truthy()) {
        Some(value) => deploy::text(value)
            .replace('%', "e-2")
            .trim()
            .parse::<f64>()
            .map_err(|_| {
                invalid(&format!(
                    "could not convert string to float: {}",
                    crate::strategy::python_repr(&deploy::text(value).replace('%', "e-2"))
                ))
            })?,
        None => 0.0,
    };
    let offset = match deploy::setup(tenant, "schedule_offset") {
        None => 0,
        Some(Json::Int(offset)) => *offset,
        Some(value) => count(&deploy::text(value)).ok_or_else(|| {
            invalid(&format!(
                "invalid literal for int() with base 10: {}",
                crate::strategy::python_repr(&deploy::text(value))
            ))
        })?,
    };
    Ok(Settings {
        actions: strings(deploy::setup(tenant, "actions_enabled")),
        default_actions: strings(deploy::setup(tenant, "default_actions")),
        mode: timerange_mode(deploy::setup(tenant, "frequency_scheduling")).to_owned(),
        skew,
        offset,
        enterprise_security: deploy::setup(tenant, "enterprise_security").is_some_and(Json::truthy),
    })
}

/// A value the block sets, Python-truthy.
fn truthy<'j>(value: Option<&'j Json>, key: &str) -> Option<&'j Json> {
    value
        .and_then(|value| value.get(key))
        .filter(|value| value.truthy())
}

/// A value the block sets, not `null`.
fn present<'j>(value: Option<&'j Json>, key: &str) -> Option<&'j Json> {
    value
        .and_then(|value| value.get(key))
        .filter(|value| !value.is_null())
}

fn flag(value: &Json) -> Json {
    Json::Int(i64::from(value.truthy()))
}

/// The search a rule deploys (`create_query`): its query and the macro that
/// maps it to the rule.
pub fn create_query(rule: &Rule, block: &Json) -> String {
    let status = block.get("status").map(deploy::text).unwrap_or_default();
    let spl = block
        .get("query")
        .and_then(Json::as_str)
        .unwrap_or_default()
        .trim();
    format!(
        "{spl}\n| eval MDR_UUID=\"{}\", MDR_status=\"{status}\" \n|`soc_macro_auto_mdr_mapping(MDR_UUID)`",
        rule.uuid
    )
}

/// `response.responders`, or `[deployment] default_responders`
/// (`resolve_responders`).
fn responders(cx: &Context<'_>, rule: &Rule) -> String {
    if let Some(authored) = rule
        .response()
        .and_then(|response| response.get("responders"))
        .filter(|value| !value.is_null())
    {
        let text = deploy::text(authored);
        if !text.trim().is_empty() {
            return text.trim().to_owned();
        }
    }
    cx.config
        .get("deployment")
        .and_then(|deployment| deployment.get("default_responders"))
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The saved search's settings from the block (`config_mdr`).
#[expect(
    clippy::too_many_lines,
    reason = "one setting after another, in the oracle's order"
)]
fn config_mdr(
    cx: &Context<'_>,
    rule: &Rule,
    block: &Json,
    settings: &Settings,
    clock: Clock,
    correlation: bool,
) -> Result<Object, CompileError> {
    let mut config = Object::new();
    let name = rule.name.trim();
    if let Some(scheduling) = truthy(Some(block), "scheduling") {
        let kind = truthy(Some(scheduling), "type").map(deploy::text);
        let schedule = truthy(Some(scheduling), "schedule");
        if kind.as_deref().map(str::to_lowercase).as_deref() == Some("real time") {
            config.insert("dispatch.earliest_time".into(), "rt".into());
            config.insert("dispatch.latest_time".into(), "rt".into());
        } else if kind.is_some() || schedule.is_some() {
            config.insert("is_scheduled".into(), Json::Int(1));
        }
        if let Some(expires) = truthy(Some(scheduling), "expires") {
            config.insert("alert.expires".into(), expires.clone());
        }
        if let Some(schedule) = schedule {
            if let Some(cron) = truthy(Some(schedule), "cron") {
                config.insert("cron_schedule".into(), cron.clone());
            } else if let Some(frequency) = truthy(Some(schedule), "frequency") {
                let frequency = deploy::text(frequency);
                let cron = match truthy(Some(schedule), "custom_time") {
                    Some(custom) => {
                        cron_to_timeframe(&frequency, "custom", Some(&deploy::text(custom)), clock)?
                    }
                    None => cron_to_timeframe(&frequency, &settings.mode, None, clock)?,
                };
                config.insert("cron_schedule".into(), cron.into());
            }
        }
        if let Some(timerange) = truthy(Some(scheduling), "timerange") {
            if let Some(lookback) = truthy(Some(timerange), "lookback") {
                config.insert(
                    "dispatch.earliest_time".into(),
                    splunk_timerange(&deploy::text(lookback), settings.skew, settings.offset)?
                        .into(),
                );
            }
            if let Some(earliest) = truthy(Some(timerange), "earliest") {
                config.insert("dispatch.earliest_time".into(), earliest.clone());
            }
            if let Some(latest) = truthy(Some(timerange), "latest") {
                config.insert("dispatch.latest_time".into(), latest.clone());
            }
        }
    }
    if let Some(trigger) = truthy(Some(block), "trigger") {
        for (key, setting) in [
            ("condition", "alert_type"),
            ("comparator", "alert_comparator"),
        ] {
            if let Some(value) = truthy(Some(trigger), key) {
                config.insert(setting.into(), value.clone());
            }
        }
        for (key, setting) in [
            ("threshold", "alert_threshold"),
            ("severity", "alert.severity"),
        ] {
            if let Some(value) = present(Some(trigger), key) {
                config.insert(setting.into(), value.clone());
            }
        }
        if let Some(value) = truthy(Some(trigger), "custom_condition") {
            config.insert("alert_condition".into(), value.clone());
        }
        if let Some(kind) = truthy(Some(trigger), "type") {
            let once = deploy::text(kind).to_lowercase() == "once";
            config.insert(
                "alert.digest_mode".into(),
                if once { "true" } else { "false" }.into(),
            );
        }
        if let Some(throttling) = truthy(Some(trigger), "throttling") {
            if let Some(duration) = truthy(Some(throttling), "duration") {
                config.insert("alert.suppress.period".into(), duration.clone());
                config.insert("alert.suppress".into(), "true".into());
            }
            if let Some(fields) = truthy(Some(throttling), "fields") {
                config.insert(
                    "alert.suppress.fields".into(),
                    strings(Some(fields)).join(", ").into(),
                );
            }
            if let Some(group) = truthy(Some(throttling), "group_name") {
                config.insert("alert.suppress.group_name".into(), group.clone());
            }
        }
    }
    if !config.contains_key("alert.severity") && rule.response().is_some() {
        let severity = match rule.alert_severity() {
            "Informational" => 2,
            "Medium" => 4,
            "High" => 5,
            "Critical" => 6,
            _ => 3,
        };
        config.insert("alert.severity".into(), Json::Int(severity));
    }
    let status = block
        .get("status")
        .and_then(Json::as_str)
        .unwrap_or_default();
    if deploy::strategy(cx, DISPLAY, status)? == StatusStrategy::Disablement {
        config.insert("disabled".into(), "true".into());
    }
    if correlation {
        config.insert("action.correlationsearch.enabled".into(), "true".into());
        config.insert(
            "action.correlationsearch.label".into(),
            format!("{name} - Rule").into(),
        );
        let mut raw: Vec<String> = strings(rule.data.get("techniques"));
        if cx.index.get("rule", &rule.uuid).is_some() {
            raw.extend(deploy::inherited_techniques(cx, DISPLAY, rule)?);
        }
        let mut techniques: Vec<String> = Vec::new();
        for technique in raw {
            if !techniques.contains(&technique) {
                techniques.push(technique);
            }
        }
        if !techniques.is_empty() {
            config.insert(
                "action.correlationsearch.annotations.mitre_attack".into(),
                techniques.join(", ").into(),
            );
        }
    }
    if let Some(actions) = truthy(Some(block), "actions") {
        if let Some(notable) = truthy(Some(actions), "notable")
            && settings.enterprise_security
        {
            if let Some(event) = truthy(Some(notable), "event") {
                for (key, setting) in [
                    ("title", "action.notable.param.rule_title"),
                    ("description", "action.notable.param.rule_description"),
                ] {
                    if let Some(value) = truthy(Some(event), key) {
                        config.insert(setting.into(), value.clone());
                    }
                }
            }
            if let Some(drilldown) = truthy(Some(notable), "drilldown") {
                for (key, setting) in [
                    ("name", "action.notable.param.drilldown_name"),
                    ("search", "action.notable.param.drilldown_search"),
                ] {
                    if let Some(value) = truthy(Some(drilldown), key) {
                        config.insert(setting.into(), value.clone());
                    }
                }
            }
            if let Some(domain) = truthy(Some(notable), "security_domain") {
                config.insert(
                    "action.notable.param.security_domain".into(),
                    deploy::text(domain).to_lowercase().into(),
                );
            }
        }
        if let Some(risk) = truthy(Some(actions), "risk")
            && settings.enterprise_security
        {
            let mut entries: Vec<Json> = Vec::new();
            if let Some(Json::Array(objects)) = truthy(Some(risk), "risk_objects") {
                for object in objects {
                    let mut entry = Object::new();
                    entry.insert("risk_object_field".into(), member(object, "field"));
                    entry.insert("risk_object_type".into(), member(object, "type"));
                    entry.insert("risk_score".into(), member(object, "score"));
                    entries.push(Json::Object(entry));
                }
            }
            if let Some(Json::Array(objects)) = truthy(Some(risk), "threat_objects") {
                for object in objects {
                    let mut entry = Object::new();
                    entry.insert("threat_object_field".into(), member(object, "field"));
                    entry.insert("threat_object_type".into(), member(object, "type"));
                    entries.push(Json::Object(entry));
                }
            }
            if !entries.is_empty() {
                // JSON for Splunk to read: written compact, not with
                // json.dumps's spaces.
                config.insert(
                    "action.risk.param._risk".into(),
                    Json::Array(entries).to_compact().into(),
                );
            }
            if let Some(message) = truthy(Some(risk), "message") {
                config.insert("action.risk.param._risk_message".into(), message.clone());
            }
        }
        if let Some(email) = truthy(Some(actions), "email") {
            for (key, setting) in [
                ("to", "action.email.to"),
                ("cc", "action.email.cc"),
                ("bcc", "action.email.bcc"),
                ("priority", "action.email.priority"),
                ("subject", "action.email.subject"),
                ("message", "action.email.message.alert"),
                ("content_type", "action.email.content_type"),
            ] {
                if let Some(value) = truthy(Some(email), key) {
                    config.insert(setting.into(), value.clone());
                }
            }
            for (key, setting) in [
                ("send_csv", "action.email.sendcsv"),
                ("send_pdf", "action.email.sendpdf"),
                ("inline_results", "action.email.inline"),
            ] {
                if let Some(value) = present(Some(email), key) {
                    config.insert(setting.into(), flag(value));
                }
            }
            if let Some(include) = truthy(Some(email), "include") {
                for (key, setting) in [
                    ("results_link", "action.email.include.results_link"),
                    ("search_string", "action.email.include.search"),
                    ("trigger_condition", "action.email.include.trigger"),
                    ("trigger_time", "action.email.include.trigger_time"),
                ] {
                    if let Some(value) = present(Some(include), key) {
                        config.insert(setting.into(), flag(value));
                    }
                }
            }
        }
    }
    config.insert("alert.managedBy".into(), responders(cx, rule).into());
    if let Some(Json::Object(advanced)) = block.get("advanced") {
        for (key, value) in advanced {
            config.insert(key.clone(), saved_search_value(value).into());
        }
    }
    config.insert("description".into(), rule.description().into());
    Ok(config)
}

/// A value of the block's `advanced` table as `savedsearches.conf` text
/// (`saved_search_value`, 0.24.0): `null` is the empty value, a boolean `1`
/// or `0` as every other boolean setting, anything else its text.
fn saved_search_value(value: &Json) -> String {
    match value {
        Json::Null => String::new(),
        Json::Bool(flag) => if *flag { "1" } else { "0" }.to_owned(),
        other => deploy::text(other),
    }
}

fn member(value: &Json, key: &str) -> Json {
    value.get(key).cloned().unwrap_or(Json::Null)
}

/// Applies the platform's `[[modifiers]]` (`_apply_flat_modifiers`): a
/// default modifier fills gaps, any other overrides; `allowed_actions`
/// narrows the actions. The actions left allowed.
fn apply_modifiers(
    modifiers: &[Json],
    config: &mut Object,
    status: &str,
    tenant: &str,
    flags: &[String],
    actions: &[String],
) -> Vec<String> {
    let mut allowed: Vec<String> = actions.to_vec();
    let mut defaults = Object::new();
    let mut overrides = Object::new();
    for modifier in modifiers {
        let conditions = modifier.get("conditions");
        let default = matches!(
            conditions.and_then(|conditions| conditions.get("default")),
            Some(Json::Bool(true))
        );
        let mut matched = default;
        if let Some(statuses) = truthy(conditions, "status")
            && strings(Some(statuses)).iter().any(|name| name == status)
        {
            matched = true;
        }
        if let Some(tenants) = truthy(conditions, "tenants") {
            matched = strings(Some(tenants)).iter().any(|name| name == tenant);
        }
        if let Some(wanted) = truthy(conditions, "flags") {
            let wanted = strings(Some(wanted));
            matched = flags.iter().any(|flag| wanted.contains(flag));
        }
        if !matched {
            continue;
        }
        if let Some(Json::Object(modifications)) = modifier.get("modifications") {
            let target = if default {
                &mut defaults
            } else {
                &mut overrides
            };
            for (key, value) in modifications {
                target.insert(key.clone(), value.clone());
            }
        }
    }
    for attributes in [&mut defaults, &mut overrides] {
        if let Some(value) = attributes.shift_remove("allowed_actions") {
            match value {
                Json::Bool(false) | Json::Null => allowed = Vec::new(),
                Json::Array(_) => allowed = strings(Some(&value)),
                _ => {}
            }
        }
    }
    for (key, value) in defaults {
        config.entry(key).or_insert(value);
    }
    for (key, value) in overrides {
        config.insert(key, value);
    }
    allowed
}

/// The actions the saved search runs (`_build_actions_config`).
fn actions_config(
    config: &mut Object,
    settings: &Settings,
    name: &str,
    rule: &Rule,
    allowed: &[String],
) -> Object {
    let mut actions = Object::new();
    if settings.actions.is_empty() {
        return actions;
    }
    let mut triggered: Vec<String> = Vec::new();
    for action in &settings.actions {
        let prefix = format!("action.{action}");
        if allowed.contains(action) && config.keys().any(|param| param.contains(&prefix)) {
            triggered.push(action.clone());
            actions.insert(prefix, Json::Int(1));
        }
    }
    if triggered.is_empty() {
        triggered = settings
            .default_actions
            .iter()
            .filter(|action| allowed.contains(action))
            .cloned()
            .collect();
    }
    if triggered.is_empty() {
        actions.insert("actions".into(), "".into());
        return actions;
    }
    actions.insert("actions".into(), triggered.join(", ").into());
    if triggered.iter().any(|action| action == "notable") {
        if !config.contains_key("action.notable.param.rule_title") {
            actions.insert("action.notable.param.rule_title".into(), name.into());
            actions.insert(
                "action.notable.param.rule_description".into(),
                rule.description().into(),
            );
            if rule.response().is_some() {
                actions.insert(
                    "action.notable.param.severity".into(),
                    rule.alert_severity().to_lowercase().into(),
                );
            }
        }
        if let Some(domain) = config
            .get("action.notable.param.security_domain")
            .filter(|value| value.truthy())
            .map(deploy::text)
        {
            config.insert(
                "action.notable.param.security_domain".into(),
                domain.to_lowercase().into(),
            );
        }
    }
    if triggered.iter().any(|action| action == "risk") {
        actions.insert("action.risk.param._risk_score".into(), Json::Int(0));
    }
    actions
}

/// The writes a deploy sends for `rule` to `tenant` when the saved search
/// does not exist yet: the create (`POST saved/searches`, name and search),
/// then the two updates of its settings (`POST saved/searches/<name>`); none
/// for a DELETION status.
pub fn compile(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: &Json,
    clock: Clock,
) -> Result<Vec<Write>, CompileError> {
    let Some(block) = rule.block(PLATFORM).filter(|block| block.truthy()) else {
        return Ok(Vec::new());
    };
    let settings = settings(tenant)?;
    let correlation = match block.get("correlation_search") {
        Some(Json::Bool(set)) => *set,
        _ => settings.enterprise_security,
    };
    let mut config = config_mdr(cx, rule, block, &settings, clock, correlation)?;
    let mut name = rule.name.trim().to_owned();
    let status = block.get("status").map(deploy::text).unwrap_or_default();
    let query = create_query(rule, block);
    if correlation {
        name.push_str(" - Rule");
    }
    let modifiers: Vec<Json> =
        match deploy::platform_config(cx, PLATFORM).and_then(|config| config.get("modifiers")) {
            Some(Json::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
    let flags = strings(block.get("flags"));
    let allowed = apply_modifiers(
        &modifiers,
        &mut config,
        &status,
        deploy::tenant_name(tenant),
        &flags,
        &settings.actions,
    );
    let actions = actions_config(&mut config, &settings, &name, rule, &allowed);
    if deploy::strategy(cx, DISPLAY, &status)? == StatusStrategy::Deletion {
        return Ok(Vec::new());
    }
    let mut first = config;
    for (key, value) in actions {
        first.insert(key, value);
    }
    first.insert("search".into(), query.clone().into());
    let mut second = Object::new();
    for key in ["alert.suppress", "is_scheduled", "actions", "search"] {
        if let Some(value) = first.shift_remove(key) {
            second.insert(key.into(), value);
        }
    }
    let mut create = Object::new();
    create.insert("name".into(), name.clone().into());
    create.insert("search".into(), query.into());
    let path = format!("saved/searches/{name}");
    let mut writes = vec![
        Write::new("POST", "saved/searches", Json::Object(create)),
        Write::new("POST", path.clone(), Json::Object(first)),
    ];
    if !second.is_empty() {
        writes.push(Write::new("POST", path, Json::Object(second)));
    }
    Ok(writes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLOCK: Clock = Clock {
        random: (7, 7),
        now: (4, 3),
    };

    #[test]
    fn frequencies_become_crons() {
        assert_eq!(
            cron_to_timeframe("15m", "random", None, CLOCK).unwrap(),
            "*/15 * * * *"
        );
        assert_eq!(
            cron_to_timeframe("2h", "current", None, CLOCK).unwrap(),
            "04 */2 * * *"
        );
        assert_eq!(
            cron_to_timeframe("2h", "random", None, CLOCK).unwrap(),
            "7 */2 * * *"
        );
        assert_eq!(
            cron_to_timeframe("1d", "custom", Some("06h30"), CLOCK).unwrap(),
            "30 06 */1 * *"
        );
        assert!(cron_to_timeframe("1d", "custom", None, CLOCK).is_err());
        assert!(cron_to_timeframe("1w", "random", None, CLOCK).is_err());
        assert!(cron_to_timeframe("xh", "random", None, CLOCK).is_err());
    }

    #[test]
    fn lookbacks_stretch_and_round_half_to_even() {
        assert_eq!(splunk_timerange("1h", 0.1, 2).unwrap(), "-68m@m");
        assert_eq!(splunk_timerange("1d", 0.0, 0).unwrap(), "-1440m@m");
        // 5 * 1.5 = 7.5 rounds to 8, 3 * 1.5 = 4.5 to 4.
        assert_eq!(splunk_timerange("5m", 0.5, 0).unwrap(), "-8m@m");
        assert_eq!(splunk_timerange("3m", 0.5, 0).unwrap(), "-4m@m");
        assert!(splunk_timerange("3s", 0.0, 0).is_err());
    }

    #[test]
    fn unset_or_unknown_modes() {
        assert_eq!(timerange_mode(None), "random");
        assert_eq!(timerange_mode(Some(&Json::Str("custom".into()))), "custom");
        assert_eq!(timerange_mode(Some(&Json::Str("hourly".into()))), "current");
    }

    #[test]
    fn modifiers_fill_gaps_override_and_narrow_actions() {
        let modifiers: Vec<Json> = serde_json::from_str(
            r#"[{"conditions":{"default":true},"modifications":{"a":"default","b":"default"}},
                {"conditions":{"status":["STAGING"]},"modifications":{"b":"staging","allowed_actions":["notable"]}},
                {"conditions":{"status":["STAGING"],"tenants":["other"]},"modifications":{"c":"x"}},
                {"conditions":{"flags":["noisy"]},"modifications":{"allowed_actions":false}}]"#,
        )
        .unwrap();
        let mut config = Object::new();
        config.insert("a".into(), "rule".into());
        let actions = vec!["notable".to_owned(), "risk".to_owned()];
        let allowed = apply_modifiers(&modifiers, &mut config, "STAGING", "es", &[], &actions);
        assert_eq!(allowed, ["notable"]);
        assert_eq!(
            Json::Object(config).to_compact(),
            r#"{"a":"rule","b":"staging"}"#
        );
        let mut config = Object::new();
        let allowed = apply_modifiers(
            &modifiers,
            &mut config,
            "PRODUCTION",
            "es",
            &["noisy".to_owned()],
            &actions,
        );
        assert!(allowed.is_empty());
    }
}
