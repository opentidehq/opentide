//! Graylog event definitions (`platforms/graylog/compile.py`, graylog-1.0):
//! the definition a rule's Graylog block deploys, and its requests.
//!
//! The author writes the query, the aggregation, the schedule, the event
//! fields and the notifications; the rest comes from the opentide rule: the
//! title, description, priority, tags and ATT&CK ids. Every request body is
//! built for the server version deploy read from `GET /api/system`
//! (graylog-1.0, "Versions"): a body never carries a property that version
//! does not define, because Graylog 6.3 accepts an unknown property on create
//! and silently drops it.
//!
//! The condition grammar is opentide-schema's
//! ([`opentide_schema::objects::platform::graylog::condition`]), the one the
//! model checks the block with.

use std::fmt;

use opentide_core::falco::{is_python_space, python_strip};
use opentide_schema::objects::platform::durations::duration_seconds;
use opentide_schema::objects::platform::graylog::PRIORITIES;
use opentide_schema::objects::platform::graylog::condition::compile_condition;

use crate::elastic::rule_techniques;
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::{Context, attack};

/// The platform's identifier.
pub const PLATFORM: &str = "graylog";

/// The platform's display name, in a failure's message.
pub const DISPLAY: &str = "Graylog";

/// `major.minor.patch` of a Graylog server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u64, pub u64, pub u64);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// The oldest supported version: below it a tenant fails
/// `graylog_version_unsupported`.
pub const MINIMUM_VERSION: Version = Version(6, 3, 0);
/// The version a dry run and `validate` build bodies for: no server is asked.
pub const PREVIEW_VERSION: Version = Version(7, 2, 0);
/// The first version of each line not affected by GHSA-j769-9gv9-65gr.
pub const FIXED_VERSIONS: [Version; 3] = [Version(6, 3, 12), Version(7, 0, 16), Version(7, 1, 12)];
/// The advisory an affected version earns a warning for.
pub const ADVISORY: &str = "GHSA-j769-9gv9-65gr";

const V7_0: Version = Version(7, 0, 0);
const V7_1: Version = Version(7, 1, 0);
const V7_2: Version = Version(7, 2, 0);

/// The priority of a block and a rule that name none (Medium).
pub const DEFAULT_PRIORITY: i64 = 2;
/// The interval of a block that sets none.
pub const DEFAULT_EVERY: &str = "5m";
/// The event limit of a filter that sets none.
pub const DEFAULT_EVENT_LIMIT: i64 = 100;
/// The time zone of a cron schedule that names none.
pub const DEFAULT_TIMEZONE: &str = "UTC";
/// The most tags a definition takes.
pub const MAX_TAGS: usize = 64;
/// The longest tag.
pub const MAX_TAG_LENGTH: usize = 128;
/// The most ATT&CK ids a definition takes.
pub const MAX_ATTACK_IDS: usize = 64;
/// The event field that carries the ATT&CK ids before 7.2.
pub const ATTACK_FIELD: &str = "attack_techniques";

/// Event definitions.
pub const DEFINITIONS_PATH: &str = "/api/events/definitions";
/// The query check.
pub const VALIDATE_PATH: &str = "/api/search/validate";

/// `(major, minor, patch)` of a `GET /api/system` version (`6.3.5+eaa4b5d`):
/// leading blanks, then `major.minor[.patch]`; `None` when it is not one
/// (`parse_version`).
pub fn parse_version(text: &str) -> Option<Version> {
    let text = text.trim_start_matches(is_python_space);
    let mut parts = [0_u64; 3];
    let mut rest = text;
    for (index, part) in parts.iter_mut().enumerate() {
        if index > 0 {
            match rest.strip_prefix('.') {
                Some(after) => rest = after,
                None if index == 2 => break,
                None => return None,
            }
        }
        let end = rest
            .find(|ch: char| !ch.is_ascii_digit())
            .unwrap_or(rest.len());
        if end == 0 {
            if index == 2 {
                // `7.2.` or `7.2.x`: the patch is optional.
                break;
            }
            return None;
        }
        *part = rest[..end].parse().ok()?;
        rest = &rest[end..];
    }
    Some(Version(parts[0], parts[1], parts[2]))
}

/// Whether `version` is affected by the access-token revocation flaw
/// (GHSA-j769-9gv9-65gr): below the fix of its line.
pub fn is_vulnerable(version: Version) -> bool {
    FIXED_VERSIONS
        .iter()
        .find(|fixed| (fixed.0, fixed.1) == (version.0, version.1))
        .is_some_and(|fixed| version < *fixed)
}

/// What a block deploys on one tenant and one server version
/// (`CompiledDefinition`).
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledDefinition {
    /// The rule's UUID.
    pub uuid: String,
    /// The definition's title.
    pub title: String,
    /// The server version the body is for.
    pub version: Version,
    /// The event definition.
    pub definition: Object,
    /// `(code, message)` warnings the version or the block earns: a field the
    /// version cannot take, a priority it collapses.
    pub warnings: Vec<(&'static str, String)>,
    /// Aliases left out because no tenant resolved them (an offline preview).
    pub unresolved: Unresolved,
}

/// Aliases left out because no tenant resolved them, by the block field that
/// names them: `streams`, then `notifications`.
pub type Unresolved = Vec<(&'static str, Vec<String>)>;

impl CompiledDefinition {
    /// The definition's `config`.
    pub fn config(&self) -> Option<&Json> {
        self.definition.get("config")
    }

    /// The `opentide.<uuid>` tag, when the version sends tags (7.2+).
    pub fn uuid_tag(&self) -> Option<String> {
        let tag = format!("opentide.{}", self.uuid).to_lowercase();
        match self.definition.get("tags") {
            Some(Json::Array(tags)) if tags.iter().any(|item| item.as_str() == Some(&tag)) => {
                Some(tag)
            }
            _ => None,
        }
    }
}

/// The rule's Graylog block, or the error naming the rule (`block_of`).
pub fn block_of(rule: &Rule) -> Result<&Json, CompileError> {
    rule.block(PLATFORM).ok_or_else(|| {
        CompileError::failed(
            DISPLAY,
            &format!("Rule {} ({}) has no graylog block", rule.uuid, rule.name),
        )
    })
}

// --- derived fields -------------------------------------------------------------

/// The rule's Enterprise ATT&CK techniques by id, sorted, then their tactics
/// in matrix order (`attack_ids`): own techniques and those inherited through
/// `detection_model`, the set elastic-1.0 uses; at most [`MAX_ATTACK_IDS`].
pub fn attack_ids(cx: &Context<'_>, rule: &Rule) -> Vec<String> {
    let mut techniques: Vec<String> = Vec::new();
    let mut stages: Vec<&'static str> = Vec::new();
    for technique in rule_techniques(cx, rule) {
        let Some(name) = cx.attack.name(&technique) else {
            continue;
        };
        if attack::non_enterprise(name) {
            continue;
        }
        for stage in cx.attack.stages(&technique) {
            if let Some((stage, _)) = attack::tactic(&stage)
                && !stages.contains(&stage)
            {
                stages.push(stage);
            }
        }
        techniques.push(technique);
    }
    techniques.sort();
    techniques.dedup();
    techniques.extend(
        attack::TACTIC_ORDER
            .iter()
            .filter(|(stage, _)| stages.contains(stage))
            .map(|(_, tactic)| (*tactic).to_owned()),
    );
    techniques.truncate(MAX_ATTACK_IDS);
    techniques
}

fn text<'a>(block: &'a Json, key: &str) -> Option<&'a str> {
    block.get(key).and_then(Json::as_str)
}

/// A non-empty string of the block (Python's truthiness of an optional
/// string).
fn set_text<'a>(block: &'a Json, key: &str) -> Option<&'a str> {
    text(block, key).filter(|value| !value.is_empty())
}

/// A string-or-list value as a list (`as_list`).
fn as_list(value: Option<&Json>) -> Vec<String> {
    match value {
        Some(Json::Str(one)) => vec![one.clone()],
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

/// The shared `name`, else the opentide rule `name` (`derive_title`).
pub fn derive_title(rule: &Rule, block: &Json) -> String {
    set_text(block, "name").unwrap_or(&rule.name).to_owned()
}

/// The rule description, whitespace collapsed; before 7.2, an `ATT&CK:` line
/// after it (`derive_description`).
pub fn derive_description(rule: &Rule, ids: &[String], version: Version) -> String {
    let mut text = rule
        .description()
        .split(is_python_space)
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if version < V7_2 && !ids.is_empty() {
        text.push_str("\n\nATT&CK: ");
        text.push_str(&ids.join(", "));
    }
    text
}

/// The block `priority`, else `response.alert_severity`, else none
/// (`priority_label`).
pub fn priority_label(rule: &Rule, block: &Json) -> Option<String> {
    if let Some(priority) = set_text(block, "priority") {
        return Some(priority.to_owned());
    }
    let severity = rule.response()?.get("alert_severity")?;
    match severity {
        Json::Null => None,
        Json::Str(text) => Some(text.clone()),
        other => Some(other.to_compact()),
    }
}

/// Graylog's priority for `label`; `Informational` is 1 before 7.1
/// (`derive_priority`).
pub fn derive_priority(label: Option<&str>, version: Version) -> i64 {
    let wanted = python_strip(label.unwrap_or_default()).to_lowercase();
    let value = PRIORITIES
        .iter()
        .zip(0_i64..)
        .find(|(name, _)| name.to_lowercase() == wanted)
        .map_or(DEFAULT_PRIORITY, |(_, value)| value);
    if value == 0 && version < V7_1 {
        1
    } else {
        value
    }
}

/// Lower-cased, any character outside `[a-z0-9_.-]` as `-`, cut at 128
/// characters (`normalise_tag`).
pub fn normalise_tag(tag: &str) -> String {
    tag.to_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '.' | '-') {
                ch
            } else {
                '-'
            }
        })
        .take(MAX_TAG_LENGTH)
        .collect()
}

/// Block tags, `opentide`, `opentide.<uuid>`, tenant tags; normalised,
/// unique, at most 64 (`derive_tags`).
pub fn derive_tags(rule: &Rule, block: &Json, tenant_tags: &[String]) -> Vec<String> {
    let candidates = as_list(block.get("tags"))
        .into_iter()
        .chain(["opentide".to_owned(), format!("opentide.{}", rule.uuid)])
        .chain(tenant_tags.iter().cloned());
    let mut tags: Vec<String> = Vec::new();
    for candidate in candidates {
        let tag = normalise_tag(&candidate);
        if !tag.is_empty() && !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    tags.truncate(MAX_TAGS);
    tags
}

fn template_provider(template: String) -> Json {
    let mut provider = Object::new();
    provider.insert("type".into(), "template-v1".into());
    provider.insert("template".into(), template.into());
    provider.insert("require_values".into(), false.into());
    Json::Object(provider)
}

/// An event field value's provider (`_provider`): a lookup, a template, or
/// a bare field name as `${source.<field>}`.
fn provider(value: &Json) -> Json {
    if let Some(lookup) = value.get("lookup") {
        let mut provider = Object::new();
        provider.insert("type".into(), "lookup-v1".into());
        provider.insert(
            "table_name".into(),
            lookup.get("table").cloned().unwrap_or(Json::Null),
        );
        provider.insert(
            "key_field".into(),
            lookup.get("key_field").cloned().unwrap_or(Json::Null),
        );
        return Json::Object(provider);
    }
    if let Some(template) = value.get("template") {
        return template_provider(template.as_str().unwrap_or_default().to_owned());
    }
    match value {
        Json::Str(field) if !field.contains("${") => {
            template_provider(format!("${{source.{field}}}"))
        }
        Json::Str(template) => template_provider(template.clone()),
        other => template_provider(other.to_compact()),
    }
}

/// `event_fields` by their value forms; before 7.2, plus
/// `attack_techniques` (`derive_field_spec`).
pub fn derive_field_spec(block: &Json, ids: &[String], version: Version) -> Object {
    let mut spec = Object::new();
    if let Some(Json::Object(fields)) = block.get("event_fields") {
        for (name, value) in fields {
            let mut field = Object::new();
            field.insert("data_type".into(), "string".into());
            field.insert("providers".into(), Json::Array(vec![provider(value)]));
            spec.insert(name.clone(), Json::Object(field));
        }
    }
    if version < V7_2 && !ids.is_empty() && !spec.contains_key(ATTACK_FIELD) {
        let mut field = Object::new();
        field.insert("data_type".into(), "string".into());
        field.insert(
            "providers".into(),
            Json::Array(vec![template_provider(ids.join(","))]),
        );
        spec.insert(ATTACK_FIELD.into(), Json::Object(field));
    }
    spec
}

/// Milliseconds in a duration (`duration_ms`).
fn duration_ms(value: &str, allow_zero: bool) -> Result<i64, CompileError> {
    duration_seconds(value, allow_zero)
        .map(|seconds| i64::try_from(seconds.saturating_mul(1000)).unwrap_or(i64::MAX))
        .map_err(|_| {
            CompileError::invalid_rule(format!(
                "Invalid duration format: {}",
                opentide_schema::configuration::repr::quote(value)
            ))
        })
}

fn schedule(block: &Json) -> Option<&Json> {
    block.get("schedule").filter(|value| !value.is_null())
}

/// The time range each run searches: `window`, else `every`, else 5 minutes
/// (`window_ms`).
pub fn window_ms(block: &Json) -> Result<i64, CompileError> {
    let value = schedule(block)
        .and_then(|schedule| set_text(schedule, "window").or_else(|| set_text(schedule, "every")))
        .unwrap_or(DEFAULT_EVERY);
    duration_ms(value, false)
}

/// The block's `streams`, else the tenant's (`stream_aliases`).
pub fn stream_aliases(block: &Json, setup: Option<&Json>) -> Vec<String> {
    let own = as_list(block.get("streams"));
    if !own.is_empty() {
        return own;
    }
    as_list(setup.and_then(|setup| setup.get("streams")))
}

/// The code of an alias a tenant does not define.
pub const ALIAS_UNKNOWN: &str = "graylog_alias_unknown";

/// What to do about an unknown alias.
pub const ALIAS_HINT: &str = "add the alias to the tenant's stream_ids or notification_ids table, \
                              or change the block's streams or notifications";

/// Each alias's id in the tenant's `table` (`_resolve`), or
/// `graylog_alias_unknown` naming the aliases it lacks.
fn resolve(
    aliases: &[String],
    setup: &Json,
    table: &str,
    kind: &str,
    tenant: Option<&str>,
) -> Result<Vec<String>, CompileError> {
    let known = setup.get(table).and_then(Json::as_object);
    let lookup = |alias: &str| {
        known
            .and_then(|known| known.get(alias))
            .and_then(Json::as_str)
    };
    let missing: Vec<&str> = aliases
        .iter()
        .map(String::as_str)
        .filter(|alias| lookup(alias).is_none())
        .collect();
    if !missing.is_empty() {
        let reason = format!(
            "{kind} alias(es) {} are not in the tenant's {table} table",
            missing.join(", ")
        );
        let reason = match tenant {
            Some(tenant) => format!(
                "tenant {}: {reason}",
                opentide_schema::configuration::repr::quote(tenant)
            ),
            None => reason,
        };
        return Err(CompileError::new(ALIAS_UNKNOWN, reason, Some(ALIAS_HINT)));
    }
    Ok(aliases
        .iter()
        .filter_map(|alias| lookup(alias).map(str::to_owned))
        .collect())
}

fn strings(values: Vec<String>) -> Json {
    Json::Array(values.into_iter().map(Json::Str).collect())
}

/// The definition's `config`, and the aliases left unresolved without a
/// tenant (`derive_config`).
pub fn derive_config(
    block: &Json,
    setup: Option<&Json>,
    tenant: Option<&str>,
) -> Result<(Object, Unresolved), CompileError> {
    let mut unresolved = Vec::new();
    let aliases = stream_aliases(block, setup);
    let streams = match setup {
        None => {
            if !aliases.is_empty() {
                unresolved.push(("streams", aliases));
            }
            Vec::new()
        }
        Some(setup) => resolve(&aliases, setup, "stream_ids", "stream", tenant)?,
    };
    let schedule = schedule(block);
    let cron = schedule.and_then(|schedule| set_text(schedule, "cron"));
    let window = window_ms(block)?;
    let every = match cron {
        Some(_) => window,
        None => duration_ms(
            schedule
                .and_then(|schedule| set_text(schedule, "every"))
                .unwrap_or(DEFAULT_EVERY),
            false,
        )?,
    };
    let mut config = Object::new();
    config.insert("type".into(), "aggregation-v1".into());
    config.insert(
        "query".into(),
        block.get("query").cloned().unwrap_or(Json::Null),
    );
    config.insert("query_parameters".into(), Json::Array(Vec::new()));
    config.insert("filters".into(), Json::Array(Vec::new()));
    config.insert("streams".into(), strings(streams));
    config.insert(
        "stream_categories".into(),
        strings(as_list(block.get("stream_categories"))),
    );
    let aggregation = block.get("aggregation").filter(|value| !value.is_null());
    match aggregation {
        Some(aggregation) => {
            let condition = text(aggregation, "condition").unwrap_or_default();
            let (tree, series) = compile_condition(condition).map_err(|error| {
                CompileError::invalid_rule(error.message).at(&[
                    "configurations",
                    PLATFORM,
                    "aggregation",
                    "condition",
                ])
            })?;
            config.insert(
                "group_by".into(),
                strings(as_list(aggregation.get("group_by"))),
            );
            config.insert("series".into(), json(&series));
            let mut conditions = Object::new();
            conditions.insert("expression".into(), json(&tree));
            config.insert("conditions".into(), Json::Object(conditions));
        }
        None => {
            config.insert("group_by".into(), Json::Array(Vec::new()));
            config.insert("series".into(), Json::Array(Vec::new()));
            let mut conditions = Object::new();
            conditions.insert("expression".into(), Json::Null);
            config.insert("conditions".into(), Json::Object(conditions));
        }
    }
    config.insert("search_within_ms".into(), Json::Int(window));
    config.insert("execute_every_ms".into(), Json::Int(every));
    config.insert("use_cron_scheduling".into(), cron.is_some().into());
    if let (Some(cron), Some(schedule)) = (cron, schedule) {
        config.insert("cron_expression".into(), cron.into());
        config.insert(
            "cron_timezone".into(),
            set_text(schedule, "timezone")
                .unwrap_or(DEFAULT_TIMEZONE)
                .into(),
        );
    }
    if aggregation.is_none() {
        let limit = match block.get("event_limit") {
            Some(Json::Int(limit)) => *limit,
            _ => DEFAULT_EVENT_LIMIT,
        };
        config.insert("event_limit".into(), Json::Int(limit));
    }
    Ok((config, unresolved))
}

/// A serde value as this crate's ordered JSON.
fn json<T: serde::Serialize>(value: &T) -> Json {
    Json::from_serialize(value).unwrap_or(Json::Null)
}

/// The event definition `rule` deploys on a server of `version`
/// (`compile_definition`).
///
/// `setup` is the tenant's `[tenants.setup]`; without one (an offline
/// preview), stream and notification aliases are left out and listed in
/// [`CompiledDefinition::unresolved`]. An alias the tenant does not define is
/// `graylog_alias_unknown`.
pub fn compile_definition(
    cx: &Context<'_>,
    rule: &Rule,
    version: Version,
    setup: Option<&Json>,
    tenant: Option<&str>,
) -> Result<CompiledDefinition, CompileError> {
    let block = block_of(rule)?;
    let ids = attack_ids(cx, rule);
    let mut warnings: Vec<(&'static str, String)> = Vec::new();
    let label = priority_label(rule, block);
    let priority = derive_priority(label.as_deref(), version);
    if label
        .as_deref()
        .is_some_and(|label| python_strip(label).to_lowercase() == "informational")
        && priority != 0
    {
        warnings.push((
            "graylog_priority_collapsed",
            format!("Graylog {version} has no Informational priority: sent as Low (1)"),
        ));
    }
    let title = derive_title(rule, block);
    let mut definition = Object::new();
    definition.insert("_scope".into(), "DEFAULT".into());
    definition.insert("title".into(), title.clone().into());
    definition.insert(
        "description".into(),
        derive_description(rule, &ids, version).into(),
    );
    definition.insert("priority".into(), Json::Int(priority));
    definition.insert(
        "alert".into(),
        match block.get("alert") {
            Some(Json::Bool(alert)) => Json::Bool(*alert),
            _ => Json::Bool(true),
        },
    );
    if let Some(remediation) = set_text(block, "remediation") {
        definition.insert("remediation_steps".into(), remediation.into());
    }
    if let Some(summary) = set_text(block, "summary") {
        if version >= V7_1 {
            definition.insert("event_summary_template".into(), summary.into());
        } else {
            warnings.push((
                "graylog_field_unsupported_version",
                format!(
                    "summary is left out: Graylog {version} has no event summary template \
                     (7.1 and later)"
                ),
            ));
        }
    }
    if version >= V7_2 {
        let tenant_tags = as_list(setup.and_then(|setup| setup.get("tags")));
        definition.insert(
            "tags".into(),
            strings(derive_tags(rule, block, &tenant_tags)),
        );
        definition.insert("tactics_techniques".into(), strings(ids.clone()));
    } else if block.get("tags").is_some_and(Json::truthy) {
        warnings.push((
            "graylog_field_unsupported_version",
            format!("tags are left out: Graylog {version} has no definition tags (7.2 and later)"),
        ));
    }
    let (config, mut unresolved) = derive_config(block, setup, tenant)?;
    definition.insert("config".into(), Json::Object(config));
    definition.insert(
        "field_spec".into(),
        Json::Object(derive_field_spec(block, &ids, version)),
    );
    definition.insert("key_spec".into(), strings(as_list(block.get("event_key"))));
    let grace_period_ms = match set_text(block, "grace_period") {
        Some(grace) => duration_ms(grace, true)?,
        None => 0,
    };
    let backlog = match block.get("backlog") {
        Some(Json::Int(backlog)) => *backlog,
        _ => 0,
    };
    let mut settings = Object::new();
    settings.insert("grace_period_ms".into(), Json::Int(grace_period_ms));
    settings.insert("backlog_size".into(), Json::Int(backlog));
    definition.insert("notification_settings".into(), Json::Object(settings));
    let notifications = as_list(block.get("notifications"));
    let notification_ids = match setup {
        None => {
            if !notifications.is_empty() {
                unresolved.push(("notifications", notifications));
            }
            Vec::new()
        }
        Some(setup) => resolve(
            &notifications,
            setup,
            "notification_ids",
            "notification",
            tenant,
        )?,
    };
    definition.insert(
        "notifications".into(),
        Json::Array(
            notification_ids
                .into_iter()
                .map(|id| {
                    let mut entry = Object::new();
                    entry.insert("notification_id".into(), id.into());
                    Json::Object(entry)
                })
                .collect(),
        ),
    );
    Ok(CompiledDefinition {
        uuid: rule.uuid.clone(),
        title,
        version,
        definition,
        warnings,
        unresolved,
    })
}

// --- requests -------------------------------------------------------------------

/// 6.3: the definition with `share_request` beside it; 7.x: `{entity,
/// share_request}` (`create_body`).
pub fn create_body(compiled: &CompiledDefinition) -> Json {
    let mut body = if compiled.version < V7_0 {
        compiled.definition.clone()
    } else {
        let mut body = Object::new();
        body.insert("entity".into(), Json::Object(compiled.definition.clone()));
        body
    };
    body.insert("share_request".into(), Json::Null);
    Json::Object(body)
}

/// The bare definition with its `id`, on every version (`update_body`).
pub fn update_body(compiled: &CompiledDefinition, definition_id: &str) -> Json {
    let mut body = compiled.definition.clone();
    body.insert("id".into(), definition_id.into());
    Json::Object(body)
}

/// `POST` here creates a definition, scheduled.
pub fn create_path() -> String {
    format!("{DEFINITIONS_PATH}?schedule=true")
}

/// `PUT` here updates a definition, scheduled or not.
pub fn update_path(definition_id: &str, enabled: bool) -> String {
    format!("{DEFINITIONS_PATH}/{definition_id}?schedule={enabled}")
}

/// `DELETE` here deletes a definition.
pub fn delete_path(definition_id: &str) -> String {
    format!("{DEFINITIONS_PATH}/{definition_id}")
}

/// The `POST /api/search/validate` body for the definition's query, streams
/// and window (`validate_body`).
pub fn validate_body(compiled: &CompiledDefinition) -> Json {
    let config = compiled.config();
    let field = |key: &str| {
        config
            .and_then(|config| config.get(key))
            .cloned()
            .unwrap_or(Json::Null)
    };
    let window = match field("search_within_ms") {
        Json::Int(ms) => ms / 1000,
        _ => 0,
    };
    let mut timerange = Object::new();
    timerange.insert("type".into(), "relative".into());
    timerange.insert("range".into(), Json::Int(window));
    let mut body = Object::new();
    body.insert("query".into(), field("query"));
    body.insert("streams".into(), field("streams"));
    body.insert("stream_categories".into(), field("stream_categories"));
    body.insert("timerange".into(), Json::Object(timerange));
    Json::Object(body)
}

/// A request as the specification's goldens write it: `{method, path, body}`
/// (`api_request`).
pub fn api_request(method: &str, path: &str, body: Option<Json>) -> Json {
    let mut request = Object::new();
    request.insert("method".into(), method.into());
    request.insert("path".into(), path.into());
    request.insert("body".into(), body.unwrap_or(Json::Null));
    Json::Object(request)
}

/// The create request (`create_request`).
pub fn create_request(compiled: &CompiledDefinition) -> Json {
    api_request("POST", &create_path(), Some(create_body(compiled)))
}

/// The update request, scheduled or not (`update_request`).
pub fn update_request(compiled: &CompiledDefinition, definition_id: &str, enabled: bool) -> Json {
    api_request(
        "PUT",
        &update_path(definition_id, enabled),
        Some(update_body(compiled, definition_id)),
    )
}

/// The setup of a tenant (`tenant.setup`), when it has one.
pub fn tenant_setup(tenant: &Json) -> Option<&Json> {
    tenant.get("setup").filter(|setup| !setup.is_null())
}

/// The create body `rule` deploys on `tenant` at [`PREVIEW_VERSION`] (none
/// for a dry run: aliases are left unresolved), the body a preview shows.
pub fn compile_body(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: Option<&Json>,
) -> Result<Json, CompileError> {
    let setup = tenant.and_then(tenant_setup);
    let name = tenant
        .and_then(|tenant| tenant.get("name"))
        .and_then(Json::as_str);
    let compiled = compile_definition(cx, rule, PREVIEW_VERSION, setup, name)?;
    Ok(create_body(&compiled))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("6.3.5+eaa4b5d"), Some(Version(6, 3, 5)));
        assert_eq!(parse_version(" 7.2"), Some(Version(7, 2, 0)));
        assert_eq!(parse_version("7.1.0-rc.1"), Some(Version(7, 1, 0)));
        assert_eq!(parse_version("7.2.x"), Some(Version(7, 2, 0)));
        assert_eq!(parse_version("7"), None);
        assert_eq!(parse_version("v7.2"), None);
        assert_eq!(parse_version(""), None);
        assert_eq!(Version(7, 2, 0).to_string(), "7.2.0");
    }

    #[test]
    fn vulnerable_versions() {
        assert!(is_vulnerable(Version(6, 3, 11)));
        assert!(!is_vulnerable(Version(6, 3, 12)));
        assert!(is_vulnerable(Version(7, 0, 15)));
        assert!(is_vulnerable(Version(7, 1, 0)));
        assert!(!is_vulnerable(Version(7, 1, 12)));
        assert!(!is_vulnerable(Version(7, 2, 0)));
        assert!(!is_vulnerable(Version(6, 2, 0)));
    }

    #[test]
    fn priorities() {
        assert_eq!(derive_priority(Some("High"), PREVIEW_VERSION), 3);
        assert_eq!(derive_priority(Some(" critical "), PREVIEW_VERSION), 4);
        assert_eq!(derive_priority(Some("Informational"), PREVIEW_VERSION), 0);
        assert_eq!(derive_priority(Some("Informational"), Version(7, 0, 9)), 1);
        assert_eq!(derive_priority(Some("Urgent"), PREVIEW_VERSION), 2);
        assert_eq!(derive_priority(None, PREVIEW_VERSION), 2);
    }

    #[test]
    fn tags() {
        assert_eq!(normalise_tag("Initial Access"), "initial-access");
        assert_eq!(normalise_tag("é.x_Y-1"), "-.x_y-1");
        assert_eq!(normalise_tag(&"a".repeat(200)).len(), MAX_TAG_LENGTH);
    }

    #[test]
    fn paths() {
        assert_eq!(create_path(), "/api/events/definitions?schedule=true");
        assert_eq!(
            update_path("abc", false),
            "/api/events/definitions/abc?schedule=false"
        );
        assert_eq!(delete_path("abc"), "/api/events/definitions/abc");
    }
}
