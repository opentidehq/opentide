//! Splunk: the saved search a deploy writes on one tenant
//! (`platforms/splunk/deployer.py` `config_mdr`, `_apply_flat_modifiers`,
//! `_build_actions_config`, `_apply_saved_search`; `client.py`
//! `create_query`, `cron_to_timeframe`, `splunk_timerange`).
//!
//! A write's `url` is the one the Splunk client sends to: the tenant's
//! saved searches under its app's namespace ([`saved_searches`]), and the
//! saved search's percent-encoded name for an update. The saved search is created
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

impl Clock {
    /// The clock of a deploy of the rule `uuid` at `now`: the minute and
    /// hour a `random` schedule runs at come from the rule's UUID
    /// ([`rule_minute_and_hour`]), so a rule deployed again as it is keeps
    /// its schedule, and `current` reads `now` in UTC.
    pub fn for_rule(uuid: &str, now: jiff::Timestamp) -> Self {
        let civil = jiff::tz::Offset::UTC.to_datetime(now);
        Self {
            random: rule_minute_and_hour(uuid),
            now: (
                u32::try_from(civil.minute()).unwrap_or(0),
                u32::try_from(civil.hour()).unwrap_or(0),
            ),
        }
    }
}

/// The minute (0 to 59) and hour (0 to 23) a `random` schedule of the rule
/// `uuid` runs at (#1711): one of the day's 1440 minutes, from an FNV-1a
/// hash of all 16 bytes of the UUID, so rules spread over the day whatever
/// their UUIDs share (`00000000-…` ones too), and a rule keeps its minute
/// on every deploy. A UUID is read in any case, with or without hyphens or
/// braces; text that is not one is hashed as it is.
pub fn rule_minute_and_hour(uuid: &str) -> (u32, u32) {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;
    let digits: Vec<u8> = opentide_core::ids::parse(uuid).map_or_else(
        || uuid.as_bytes().to_vec(),
        |parsed| parsed.as_bytes().to_vec(),
    );
    let hash = digits.iter().fold(OFFSET, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
    });
    let minute_of_day = u32::try_from(hash % 1440).unwrap_or(0);
    (minute_of_day % 60, minute_of_day / 60)
}

/// The frequency mode (`correct_timerange_mode`): unset is `random`, an
/// unknown value `current`.
fn timerange_mode(value: Option<&Json>) -> &str {
    match value.filter(|value| value.is_filled()) {
        None => "random",
        Some(Json::Str(mode)) if matches!(mode.as_str(), "random" | "current" | "custom") => mode,
        Some(_) => "current",
    }
}

/// A whole count, surrounding spaces allowed.
fn count(text: &str) -> Option<i64> {
    text.trim().parse().ok()
}

fn invalid(message: &str) -> CompileError {
    CompileError::failed(DISPLAY, message)
}

/// The cron of a frequency (`cron_to_timeframe`): `15m`, `2h` or `1d`.
/// Without a `clock` (a dry run), the minute and hour a `random` or
/// `current` schedule runs at are the placeholders `<send-time:minute>` and
/// `<send-time:hour>`. [`compile`] knows the rule, so its dry run shows a
/// `random` schedule's minute and hour, which come from the rule's UUID
/// ([`rule_minute_and_hour`]).
pub fn cron_to_timeframe(
    frequency: &str,
    mode: &str,
    custom_time: Option<&str>,
    clock: Option<Clock>,
) -> Result<String, CompileError> {
    timeframe(
        frequency,
        mode,
        custom_time,
        clock.map(|clock| clock.random),
        clock.map(|clock| clock.now),
    )
}

/// [`cron_to_timeframe`] with the `random` minute and hour and the `now`
/// ones each known or not: one not known is a `<send-time:…>` placeholder.
fn timeframe(
    frequency: &str,
    mode: &str,
    custom_time: Option<&str>,
    random: Option<(u32, u32)>,
    now: Option<(u32, u32)>,
) -> Result<String, CompileError> {
    let mut chars = frequency.chars();
    let unit = chars.next_back();
    let count = count(chars.as_str()).ok_or_else(|| {
        invalid(&format!(
            "frequency {frequency:?} must be a whole number followed by m, h or d"
        ))
    })?;
    let (minute, hour) = match (mode, random, now) {
        ("random", None, _) | ("current", _, None) => {
            (deploy::send_time("minute"), deploy::send_time("hour"))
        }
        ("random", Some((minute, hour)), _) => (minute.to_string(), hour.to_string()),
        ("current", _, Some((minute, hour))) => (format!("{minute:02}"), format!("{hour:02}")),
        _ => {
            let Some(custom) = custom_time.filter(|custom| !custom.is_empty()) else {
                return Err(invalid(
                    "When selecting a custom time, you need to input a time in the correct \
                     format: HHhmm.",
                ));
            };
            let parts: Vec<&str> = custom.split('h').collect();
            let [hour, minute] = parts.as_slice() else {
                return Err(invalid(&format!("custom_time {custom:?} is not HHhmm")));
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
/// rounded half to even.
pub fn splunk_timerange(time: &str, skew: f64, offset: i64) -> Result<String, CompileError> {
    let mut chars = time.chars();
    let unit = chars.next_back();
    let count = count(chars.as_str()).ok_or_else(|| {
        invalid(&format!(
            "lookback {time:?} must be a whole number followed by m, h or d"
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
    let skew = match deploy::setup(tenant, "allow_skew").filter(|value| value.is_filled()) {
        Some(value) => deploy::text(value)
            .replace('%', "e-2")
            .trim()
            .parse::<f64>()
            .map_err(|_| {
                invalid(&format!(
                    "allow_skew must be a number or a percentage, got {:?}",
                    deploy::text(value)
                ))
            })?,
        None => 0.0,
    };
    let offset = match deploy::setup(tenant, "schedule_offset") {
        None => 0,
        Some(Json::Int(offset)) => *offset,
        Some(value) => count(&deploy::text(value)).ok_or_else(|| {
            invalid(&format!(
                "schedule_offset must be an integer, got {:?}",
                deploy::text(value)
            ))
        })?,
    };
    Ok(Settings {
        actions: strings(deploy::setup(tenant, "actions_enabled")),
        default_actions: strings(deploy::setup(tenant, "default_actions")),
        mode: timerange_mode(deploy::setup(tenant, "frequency_scheduling")).to_owned(),
        skew,
        offset,
        enterprise_security: enterprise_security(tenant)?,
    })
}

/// Whether the tenant runs Splunk Enterprise Security: `enterprise_security`
/// is `true`, or unset and off. Any other value, a `$NAME` placeholder
/// included, is an error that names the key.
pub fn enterprise_security(tenant: &Json) -> Result<bool, CompileError> {
    deploy::setup_switch(tenant, "enterprise_security", false).map_err(|message| invalid(&message))
}

/// A value the block sets: not `null` and not an empty string, list or
/// mapping.
fn filled<'j>(value: Option<&'j Json>, key: &str) -> Option<&'j Json> {
    value
        .and_then(|value| value.get(key))
        .filter(|value| value.is_filled())
}

/// A value the block sets, not `null`.
fn present<'j>(value: Option<&'j Json>, key: &str) -> Option<&'j Json> {
    value
        .and_then(|value| value.get(key))
        .filter(|value| !value.is_null())
}

/// A switch as Splunk's `1` or `0`.
fn flag(value: &Json) -> Json {
    Json::Int(i64::from(value.is_true()))
}

/// The search a rule deploys: its block's `query`, trimmed, exactly as
/// the author wrote it. Nothing is appended (0.28.1 appended an `eval` of
/// `MDR_UUID` and `MDR_status` and a site's mapping macro).
pub fn create_query(block: &Json) -> String {
    block
        .get("query")
        .and_then(Json::as_str)
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// What starts the last line of a saved search's `description`, before the
/// rule's UUID: how a deploy finds the saved searches an earlier name of the
/// rule left (#1657), with no state and nothing added to the search.
pub const RULE_MARKER: &str = "opentide rule ";

/// *description* with the line that names the rule *uuid* after it.
pub fn described(description: &str, uuid: &str) -> String {
    let description = description.trim_end();
    if description.is_empty() {
        format!("{RULE_MARKER}{uuid}")
    } else {
        format!("{description}\n\n{RULE_MARKER}{uuid}")
    }
}

/// The description a retirement sends to name *rule* (the rule's own,
/// [`described`]), which [`compile`] leaves out for a DELETION status: the
/// Splunk `Deployer` deletes, after the saved search, the ones an earlier
/// name of the rule left.
pub fn retired_description(rule: &Rule) -> String {
    described(rule.description(), &crate::rule::canonical_uuid(&rule.uuid))
}

/// The rule a saved search's *description* names ([`described`]): the
/// UUID on its last line, when that line is the marker's.
pub fn marked_rule(description: &str) -> Option<&str> {
    description
        .lines()
        .last()?
        .trim()
        .strip_prefix(RULE_MARKER)
        .map(str::trim)
        .filter(|uuid| !uuid.is_empty())
}

/// The saved search's settings from the block (0.28.1's `config_mdr`).
#[expect(
    clippy::too_many_lines,
    reason = "one setting after another, in the oracle's order"
)]
fn saved_search_settings(
    cx: &Context<'_>,
    rule: &Rule,
    block: &Json,
    settings: &Settings,
    clock: Option<Clock>,
    correlation: bool,
) -> Result<Object, CompileError> {
    let mut config = Object::new();
    let name = rule.name.trim();
    if let Some(scheduling) = filled(Some(block), "scheduling") {
        let kind = filled(Some(scheduling), "type").map(deploy::text);
        let schedule = filled(Some(scheduling), "schedule");
        if kind.as_deref().map(str::to_lowercase).as_deref() == Some("real time") {
            config.insert("dispatch.earliest_time".into(), "rt".into());
            config.insert("dispatch.latest_time".into(), "rt".into());
        } else if kind.is_some() || schedule.is_some() {
            config.insert("is_scheduled".into(), Json::Int(1));
        }
        if let Some(expires) = filled(Some(scheduling), "expires") {
            config.insert("alert.expires".into(), expires.clone());
        }
        if let Some(schedule) = schedule {
            if let Some(cron) = filled(Some(schedule), "cron") {
                config.insert("cron_schedule".into(), cron.clone());
            } else if let Some(frequency) = filled(Some(schedule), "frequency") {
                let frequency = deploy::text(frequency);
                // A drawn schedule is the rule's own, known without a
                // clock; the current one is the send's (#1711).
                let random =
                    clock.map_or_else(|| rule_minute_and_hour(&rule.uuid), |clock| clock.random);
                let now = clock.map(|clock| clock.now);
                let cron = match filled(Some(schedule), "custom_time") {
                    Some(custom) => timeframe(
                        &frequency,
                        "custom",
                        Some(&deploy::text(custom)),
                        Some(random),
                        now,
                    )?,
                    None => timeframe(&frequency, &settings.mode, None, Some(random), now)?,
                };
                config.insert("cron_schedule".into(), cron.into());
            }
        }
        if let Some(timerange) = filled(Some(scheduling), "timerange") {
            if let Some(lookback) = filled(Some(timerange), "lookback") {
                config.insert(
                    "dispatch.earliest_time".into(),
                    splunk_timerange(&deploy::text(lookback), settings.skew, settings.offset)?
                        .into(),
                );
            }
            if let Some(earliest) = filled(Some(timerange), "earliest") {
                config.insert("dispatch.earliest_time".into(), earliest.clone());
            }
            if let Some(latest) = filled(Some(timerange), "latest") {
                config.insert("dispatch.latest_time".into(), latest.clone());
            }
        }
    }
    if let Some(trigger) = filled(Some(block), "trigger") {
        for (key, setting) in [
            ("condition", "alert_type"),
            ("comparator", "alert_comparator"),
        ] {
            if let Some(value) = filled(Some(trigger), key) {
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
        if let Some(value) = filled(Some(trigger), "custom_condition") {
            config.insert("alert_condition".into(), value.clone());
        }
        if let Some(kind) = filled(Some(trigger), "type") {
            let once = deploy::text(kind).to_lowercase() == "once";
            config.insert(
                "alert.digest_mode".into(),
                if once { "true" } else { "false" }.into(),
            );
        }
        if let Some(throttling) = filled(Some(trigger), "throttling") {
            if let Some(duration) = filled(Some(throttling), "duration") {
                config.insert("alert.suppress.period".into(), duration.clone());
                config.insert("alert.suppress".into(), "true".into());
            }
            if let Some(fields) = filled(Some(throttling), "fields") {
                config.insert(
                    "alert.suppress.fields".into(),
                    strings(Some(fields)).join(", ").into(),
                );
            }
            if let Some(group) = filled(Some(throttling), "group_name") {
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
    if let Some(actions) = filled(Some(block), "actions") {
        if let Some(notable) = filled(Some(actions), "notable")
            && settings.enterprise_security
        {
            if let Some(event) = filled(Some(notable), "event") {
                for (key, setting) in [
                    ("title", "action.notable.param.rule_title"),
                    ("description", "action.notable.param.rule_description"),
                ] {
                    if let Some(value) = filled(Some(event), key) {
                        config.insert(setting.into(), value.clone());
                    }
                }
            }
            if let Some(drilldown) = filled(Some(notable), "drilldown") {
                for (key, setting) in [
                    ("name", "action.notable.param.drilldown_name"),
                    ("search", "action.notable.param.drilldown_search"),
                ] {
                    if let Some(value) = filled(Some(drilldown), key) {
                        config.insert(setting.into(), value.clone());
                    }
                }
            }
            if let Some(domain) = filled(Some(notable), "security_domain") {
                config.insert(
                    "action.notable.param.security_domain".into(),
                    deploy::text(domain).to_lowercase().into(),
                );
            }
        }
        if let Some(risk) = filled(Some(actions), "risk")
            && settings.enterprise_security
        {
            let mut entries: Vec<Json> = Vec::new();
            if let Some(Json::Array(objects)) = filled(Some(risk), "risk_objects") {
                for object in objects {
                    let mut entry = Object::new();
                    entry.insert("risk_object_field".into(), member(object, "field"));
                    entry.insert("risk_object_type".into(), member(object, "type"));
                    entry.insert("risk_score".into(), member(object, "score"));
                    entries.push(Json::Object(entry));
                }
            }
            if let Some(Json::Array(objects)) = filled(Some(risk), "threat_objects") {
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
            if let Some(message) = filled(Some(risk), "message") {
                config.insert("action.risk.param._risk_message".into(), message.clone());
            }
        }
        if let Some(email) = filled(Some(actions), "email") {
            for (key, setting) in [
                ("to", "action.email.to"),
                ("cc", "action.email.cc"),
                ("bcc", "action.email.bcc"),
                ("priority", "action.email.priority"),
                ("subject", "action.email.subject"),
                ("message", "action.email.message.alert"),
                ("content_type", "action.email.content_type"),
            ] {
                if let Some(value) = filled(Some(email), key) {
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
            if let Some(include) = filled(Some(email), "include") {
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
    // Empty, Splunk's own default: opentide sets nothing here, and an update
    // sends only the settings it writes, so a saved search 0.28.1 deployed
    // (which put the rule's responders here) would otherwise keep them.
    // `advanced` can still set it.
    config.insert("alert.managedBy".into(), "".into());
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
        if let Some(statuses) = filled(conditions, "status")
            && strings(Some(statuses)).iter().any(|name| name == status)
        {
            matched = true;
        }
        if let Some(tenants) = filled(conditions, "tenants") {
            matched = strings(Some(tenants)).iter().any(|name| name == tenant);
        }
        if let Some(wanted) = filled(conditions, "flags") {
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
            .filter(|value| value.is_filled())
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
/// does not exist yet: the create (`POST .../saved/searches/`, name and
/// search), then the two updates of its settings
/// (`POST .../saved/searches/<name>`), each with the `search` first; none
/// for a DELETION status. Without a `clock` (a dry run), a schedule read
/// at send time (`current`) is written with placeholders
/// ([`cron_to_timeframe`]), and a drawn one (`random`) with the rule's own
/// minute and hour ([`rule_minute_and_hour`]), as a deploy writes it.
pub fn compile(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: &Json,
    clock: Option<Clock>,
) -> Result<Vec<Write>, CompileError> {
    let Some(block) = rule.block(PLATFORM).filter(|block| block.is_filled()) else {
        return Ok(Vec::new());
    };
    let settings = settings(tenant)?;
    let correlation = match block.get("correlation_search") {
        Some(Json::Bool(set)) => *set,
        _ => settings.enterprise_security,
    };
    let mut config = saved_search_settings(cx, rule, block, &settings, clock, correlation)?;
    let mut name = rule.name.trim().to_owned();
    let status = block.get("status").map(deploy::text).unwrap_or_default();
    let query = create_query(block);
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
    let description = first
        .get("description")
        .map(deploy::text)
        .unwrap_or_default();
    first.insert(
        "description".into(),
        described(&description, &crate::rule::canonical_uuid(&rule.uuid)).into(),
    );
    // Each update sends the saved search's `search` first, as Splunk's REST
    // API takes it (`SavedSearch.update`): on a new saved search, the one
    // just created.
    let searched = |settings: Object| {
        let mut body = Object::new();
        body.insert("search".into(), query.clone().into());
        body.extend(settings.into_iter().filter(|(key, _)| key != "search"));
        Json::Object(body)
    };
    let mut second = Object::new();
    for key in ["alert.suppress", "is_scheduled", "actions"] {
        if let Some(value) = first.shift_remove(key) {
            second.insert(key.into(), value);
        }
    }
    let mut create = Object::new();
    create.insert("name".into(), name.clone().into());
    create.insert("search".into(), query.clone().into());
    let collection = saved_searches(tenant);
    let path = format!("{collection}{}", segment(&name));
    Ok(vec![
        Write::new("POST", collection, Json::Object(create)),
        Write::new("POST", path.clone(), searched(first)),
        Write::new("POST", path, searched(second)),
    ])
}

/// The port a tenant that names none is reached on.
pub const DEFAULT_PORT: &str = "8089";

/// `value` as one segment of a request's path: percent-encoded, unless it is
/// a dry run's `<tenant:KEY>` placeholder.
fn segment(value: &str) -> String {
    if deploy::is_tenant_value(value) {
        return value.to_owned();
    }
    percent_encoding::utf8_percent_encode(value, deploy::PATH_SEGMENT).to_string()
}

/// The URL of `tenant`'s saved searches, as a deploy sends to it:
/// `https://<url>:<port>/servicesNS/nobody/<app>/saved/searches/`, the port
/// `8089` and the app `search` when the tenant names none.
pub fn saved_searches(tenant: &Json) -> String {
    let host = deploy::setup_text(tenant, "url");
    let port = deploy::setup(tenant, "port").map_or_else(
        || DEFAULT_PORT.to_owned(),
        |port| {
            let text = deploy::text(port);
            let text = text.trim();
            text.parse::<u16>()
                .map_or_else(|_| text.to_owned(), |port| port.to_string())
        },
    );
    let app = deploy::setup(tenant, "app").map_or_else(|| "search".to_owned(), deploy::text);
    format!(
        "https://{}:{port}/servicesNS/nobody/{}/saved/searches/",
        host.trim(),
        segment(&app)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLOCK: Clock = Clock {
        random: (7, 7),
        now: (4, 3),
    };

    fn es_tenant(setup: &str) -> Json {
        serde_json::from_str(&format!(r#"{{"setup":{{{setup}}}}}"#)).unwrap()
    }

    /// `enterprise_security` is a switch: `true` turns it on, `false` or
    /// no setting leaves it off.
    #[test]
    fn enterprise_security_is_read_as_a_switch() {
        let on = |setup: &str| settings(&es_tenant(setup)).unwrap().enterprise_security;
        assert!(on(r#""enterprise_security": true"#));
        assert!(!on(r#""enterprise_security": false"#));
        assert!(!on(r#""enterprise_security": null"#));
        assert!(!on(""));
    }

    /// Nothing but a boolean is a switch: `0`, `""`, `"no"` and `"true"` are
    /// refused, naming the key, and so is a `$NAME` placeholder, which the
    /// compile step does not resolve.
    #[test]
    fn enterprise_security_refuses_what_is_not_a_boolean() {
        for value in ["0", "1", r#""""#, r#""no""#, r#""true""#, "[]", "1.5"] {
            let error = settings(&es_tenant(&format!(r#""enterprise_security": {value}"#)))
                .err()
                .unwrap_or_else(|| panic!("{value} was accepted"));
            assert!(
                error
                    .reason
                    .contains("enterprise_security must be true or false, got"),
                "{value}: {}",
                error.reason
            );
        }
        let error =
            enterprise_security(&es_tenant(r#""enterprise_security": "$SPLUNK_ES""#)).unwrap_err();
        assert!(
            error.reason.contains(
                "enterprise_security is the placeholder \"$SPLUNK_ES\", \
                 which is not resolved for this setting: write true or false"
            ),
            "{}",
            error.reason
        );
    }

    #[test]
    fn frequencies_become_crons() {
        assert_eq!(
            cron_to_timeframe("15m", "random", None, Some(CLOCK)).unwrap(),
            "*/15 * * * *"
        );
        assert_eq!(
            cron_to_timeframe("2h", "current", None, Some(CLOCK)).unwrap(),
            "04 */2 * * *"
        );
        assert_eq!(
            cron_to_timeframe("2h", "random", None, Some(CLOCK)).unwrap(),
            "7 */2 * * *"
        );
        assert_eq!(
            cron_to_timeframe("1d", "custom", Some("06h30"), Some(CLOCK)).unwrap(),
            "30 06 */1 * *"
        );
        // A dry run's schedule: the minute and hour are the send's.
        assert_eq!(
            cron_to_timeframe("2h", "random", None, None).unwrap(),
            "<send-time:minute> */2 * * *"
        );
        assert_eq!(
            cron_to_timeframe("1d", "current", None, None).unwrap(),
            "<send-time:minute> <send-time:hour> */1 * *"
        );
        assert_eq!(
            cron_to_timeframe("1d", "custom", Some("06h30"), None).unwrap(),
            "30 06 */1 * *"
        );
        assert!(cron_to_timeframe("1d", "custom", None, Some(CLOCK)).is_err());
        assert!(cron_to_timeframe("1w", "random", None, Some(CLOCK)).is_err());
        assert!(cron_to_timeframe("xh", "random", None, Some(CLOCK)).is_err());
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

    /// A count or a setting that does not read as a number names itself
    /// and what it must be.
    #[test]
    fn unreadable_numbers_name_the_setting() {
        let reason = |error: CompileError| error.reason;
        assert_eq!(
            reason(cron_to_timeframe("xh", "random", None, Some(CLOCK)).unwrap_err()),
            "Splunk cannot compile this rule: frequency \"xh\" must be a whole number followed \
             by m, h or d"
        );
        assert_eq!(
            reason(splunk_timerange("1.5h", 0.0, 0).unwrap_err()),
            "Splunk cannot compile this rule: lookback \"1.5h\" must be a whole number \
             followed by m, h or d"
        );
        let tenant = |setup: &str| -> Json {
            serde_json::from_str(&format!(r#"{{"setup":{{{setup}}}}}"#)).unwrap()
        };
        assert_eq!(
            reason(
                settings(&tenant(r#""schedule_offset":"soon""#))
                    .err()
                    .unwrap()
            ),
            "Splunk cannot compile this rule: schedule_offset must be an integer, got \"soon\""
        );
        assert_eq!(
            reason(settings(&tenant(r#""allow_skew":"lots""#)).err().unwrap()),
            "Splunk cannot compile this rule: allow_skew must be a number or a percentage, got \
             \"lots\""
        );
        let read = settings(&tenant(r#""allow_skew":"10%","schedule_offset":" 2 ""#)).unwrap();
        assert!((read.skew - 0.1).abs() < 1e-9);
        assert_eq!(read.offset, 2);
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

    /// A rule's `random` schedule comes from all 16 bytes of its UUID
    /// (#1711): the same on every deploy and in every spelling of the UUID,
    /// and spread over the day even for UUIDs that share their first bytes,
    /// as hand-numbered or imported ones do.
    #[test]
    fn a_rules_random_schedule_comes_from_its_whole_uuid() {
        let uuid = "00000000-0000-4000-8099-000000000001";
        let drawn = rule_minute_and_hour(uuid);
        assert_eq!(drawn, PINNED);
        for spelling in [
            "00000000-0000-4000-8099-000000000001".to_uppercase(),
            "{00000000-0000-4000-8099-000000000001}".to_owned(),
            "urn:uuid:00000000-0000-4000-8099-000000000001".to_owned(),
            "00000000000040008099000000000001".to_owned(),
        ] {
            assert_eq!(rule_minute_and_hour(&spelling), drawn, "{spelling}");
        }
        let now = jiff::Timestamp::from_second(3_600 * 5 + 60 * 42).unwrap();
        assert_eq!(
            Clock::for_rule(uuid, now),
            Clock {
                random: drawn,
                now: (42, 5)
            }
        );
        // The tests' own UUIDs, which share all but their last byte.
        let three: std::collections::BTreeSet<(u32, u32)> = (1..=3)
            .map(|n| rule_minute_and_hour(&format!("00000000-0000-4000-8099-00000000000{n}")))
            .collect();
        assert_eq!(three.len(), 3, "{three:?}");
        // A thousand UUIDs that differ only in their last bytes reach every
        // hour and nearly every minute.
        let (mut minutes, mut hours) = (
            std::collections::BTreeSet::new(),
            std::collections::BTreeSet::new(),
        );
        for n in 0..1000 {
            let (minute, hour) = rule_minute_and_hour(&format!("00000000-0000-4000-8099-{n:012}"));
            assert!(minute < 60 && hour < 24, "{minute} {hour}");
            minutes.insert(minute);
            hours.insert(hour);
        }
        assert_eq!(hours.len(), 24, "{hours:?}");
        assert!(minutes.len() >= 55, "{minutes:?}");
        // Text that is not a UUID is hashed as it is, still in range.
        let (minute, hour) = rule_minute_and_hour("not a uuid");
        assert!(minute < 60 && hour < 24);
    }

    /// [`rule_minute_and_hour`] of `00000000-0000-4000-8099-000000000001`.
    const PINNED: (u32, u32) = (9, 13);
}
