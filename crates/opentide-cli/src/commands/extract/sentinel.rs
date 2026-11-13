//! `opentide generate extract sentinel` (UC-4.4e, #834;
//! `extraction/sentinel_importer.py`): the analytics rules of each Sentinel
//! tenant, listed through the connectors' ARM client
//! ([`opentide_connectors::sentinel::Sentinel::list`]), dumped as
//! `output-<tenant>.json` and written as opentide rule files under
//! `Imported/`.
//!
//! A listed rule is read as the oracle read it (`alert_rule_as_flat_dict`):
//! its `properties` merged up and every key in snake case, the custom
//! details' keys kept. Each file is the oracle's template filled in, byte for
//! byte, but for its one-line scalars: the oracle quoted them with PyYAML
//! (`_scalar`), and here serde-saphyr's emitter writes them, with the
//! settings of Elastic's files ([`super::rule_yaml`]): a string that must be
//! quoted is double-quoted (the approved differences of #834).

use std::time::{Duration, Instant};

use opentide_compile::json::{Json as CJson, Object};
use opentide_connectors::connector::TenantContext;
use opentide_connectors::sentinel::Sentinel;
use opentide_connectors::text::json_text;
use opentide_connectors::{ConnectorError, Environment};
use tokio_util::sync::CancellationToken;

use super::{
    Context, Outcome, block_on, configured, format, json_string, key_error, report,
    sanitize_filename, strip, tenant, under, write_text,
};

const SENTINEL: &str = "sentinel";
const LOGGER: &str = "opentide.extraction.sentinel_importer";
/// Every line holding it is left out of a file (`OPENTIDE::REMOVE`).
const REMOVE: &str = "OPENTIDE::REMOVE";

const GROUPING_CONFIGURATION: &str = "      grouping_lookback: {grouping_lookback}\n      matching: {grouping_matching_method}\n      {group_by_entities}\n      {group_by_alert_details}\n      {group_by_custom_details}";
const DYNAMIC_PROPERTIES_TEMPLATE: &str = "      #- property: \n        #column: ";
const DYNAMIC_PROPERTIES: &str = "      - property: {property} \n        column: {column}";
const ENTITIES_TEMPLATE: &str =
    "  #entities:\n    #- entity: \n      #mappings:\n        #- identifier: \n          #column: ";
const ENTITIES_MAPPINGS: &str = "        - identifier: {identifier} \n          column: {column}";
const ENTITIES: &str = "    - entity: {entity} \n      mappings:\n{mappings}";
const TRIGGER_TEMPLATE: &str = "  #trigger:\n    #operator: \n    #threshold: ";
const TRIGGER: &str = "  trigger:\n    operator: {operator}\n    threshold: {threshold}";
const SCHEDULING: &str =
    "  scheduling:\n    #nrt: false\n    frequency: {frequency} \n    lookback: {lookback}";
const NRT_SCHEDULING: &str = "  scheduling:\n    nrt: true";
const CUSTOM_DETAILS_TEMPLATE: &str = "      #- key: \n        #column: ";
const CUSTOM_DETAILS: &str = "      - key: {key} \n        column: {column}";
const MDR: &str = "\nname: {rule_name}\n\n#references:\n  #public:\n    #1: \n  #internal:\n    #a: \n\nmetadata:\n  uuid: {rule_uuid}\n  schema: rule::1.0\n  version: \n  created: {rule_creation}\n  modified: {rule_modified}\n  tlp: amber\n  author: {rule_author} \n  #contributors:\n    #-\n\ndescription: {rule_description_style}\n  {rule_description}\n#detection_model: \n\nresponse:\n  alert_severity: {rule_severity}\n  #playbook: https://\n  #responders: \n  #procedure:\n    #analysis: |\n      #...\n    #searches:\n      #- purpose: |\n          #...\n        #system: \n        #query: |\n          #...\n    #containment: |\n      #...\n\nconfigurations:\n  sentinel: \n{sentinel}\n";
const BLOCK: &str = "\n  schema: platform::sentinel::1.0\n  status: {status}\n  tenants:\n    - {tenant_name}\n  #contributors:\n    #-\n \n{trigger}\n  \n{scheduling}\n  \n  alert:\n    create_incident: {create_incident}\n    suppression: {alert_suppression}\n    {alert_title_commented}title: {alert_title_override} \n    {alert_description_commented}description: {alert_description_style}\n      {alert_description_override}\n    {custom_details_commented}custom_details:\n{custom_details}\n    {dynamic_properties_commented}dynamic_properties:\n{dynamic_properties}\n    {tactics}\n    {techniques}\n\n  grouping:\n    event: {event_aggregation}\n  \n    alert:\n      enabled: {alert_grouping_enabled}\n      {reopen_closed_incidents_commented}reopen_closed_incidents: {reopen_closed_incidents}\n{grouping_configuration}\n\n  {entities_commented}entities:\n{entities}\n  \n  query: {query_style}\n    {query}\n";

// ------------------------------------------------- the listed rule's data

/// Keys whose values are maps of user-chosen keys (`_MAP_FIELDS`): their
/// keys are data and keep their case.
const MAP_FIELDS: [&str; 2] = ["customDetails", "custom_details"];

/// `_snake_case`: an underscore before each ASCII capital but the first
/// character, then the whole name lower-cased.
fn snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (index, c) in name.chars().enumerate() {
        if index > 0 && c.is_ascii_uppercase() {
            out.push('_');
        }
        out.push(c);
    }
    out.to_lowercase()
}

/// `_snake_keys`: every key of every object in snake case, but those of a
/// map field's value. Two keys that meet keep the first one's place and the
/// last one's value, as a dict built key by key does.
fn snake_keys(value: &CJson) -> CJson {
    match value {
        CJson::Array(items) => CJson::Array(items.iter().map(snake_keys).collect()),
        CJson::Object(object) => {
            let mut out = Object::new();
            for (key, item) in object {
                let item = if MAP_FIELDS.contains(&key.as_str()) {
                    item.clone()
                } else {
                    snake_keys(item)
                };
                out.insert(snake_case(key), item);
            }
            CJson::Object(out)
        }
        other => other.clone(),
    }
}

/// `alert_rule_as_flat_dict`: ARM nests a rule under `properties`; they are
/// merged up (a property replaces a top-level key of its name) and the keys
/// converted, so `properties.displayName` reads as `display_name`.
pub(crate) fn flat_rule(rule: &CJson) -> CJson {
    let mut merged = Object::new();
    let mut properties = None;
    if let CJson::Object(object) = rule {
        for (key, value) in object {
            if key == "properties" {
                properties = Some(value);
            } else {
                merged.insert(key.clone(), value.clone());
            }
        }
    }
    if let Some(CJson::Object(properties)) = properties {
        for (key, value) in properties {
            merged.insert(key.clone(), value.clone());
        }
    }
    snake_keys(&CJson::Object(merged))
}

/// `value` as a file: serde_json's pretty printer at four spaces, UTF-8,
/// with a final newline.
pub(crate) fn json_indent4(value: &CJson) -> String {
    opentide_compile::generate::json_text::pretty(value, 4)
}

// ------------------------------------------------------ the oracle's helpers

/// The name of a JSON value's Python type, as an `AttributeError` names it.
fn type_name(value: &CJson) -> &'static str {
    match value {
        CJson::Null => "NoneType",
        CJson::Bool(_) => "bool",
        CJson::Int(_) => "int",
        CJson::Float(_) => "float",
        CJson::Str(_) => "str",
        CJson::Array(_) => "list",
        CJson::Object(_) => "dict",
    }
}

fn no_attribute(value: &CJson, attribute: &str) -> String {
    format!(
        "AttributeError: '{}' object has no attribute '{attribute}'",
        type_name(value)
    )
}

/// `mapping.get(key, {})`: the mapping at `key`, none when it is missing;
/// any other value fails the run where the oracle called `.get` on it.
fn mapping<'j>(object: &'j Object, key: &str) -> Result<Option<&'j Object>, String> {
    match object.get(key) {
        None => Ok(None),
        Some(CJson::Object(inner)) => Ok(Some(inner)),
        Some(other) => Err(no_attribute(other, "get")),
    }
}

/// `mapping.get(key) or {}`: the mapping at `key`, none when it is falsy.
fn mapping_or_empty<'j>(object: &'j Object, key: &str) -> Result<Option<&'j Object>, String> {
    match object.get(key) {
        Some(value) if !value.truthy() => Ok(None),
        other => match other {
            None => Ok(None),
            Some(CJson::Object(inner)) => Ok(Some(inner)),
            Some(other) => Err(no_attribute(other, "get")),
        },
    }
}

/// `mapping[key]`.
fn required<'j>(object: &'j Object, key: &str) -> Result<&'j CJson, String> {
    object.get(key).ok_or_else(|| key_error(key))
}

/// `mapping[key]` used as a string (`.split`, `.removeprefix`).
fn required_text<'j>(object: &'j Object, key: &str, method: &str) -> Result<&'j str, String> {
    match required(object, key)? {
        CJson::Str(text) => Ok(text),
        other => Err(no_attribute(other, method)),
    }
}

/// `mapping.get(key)` when it is truthy.
fn truthy<'j>(object: &'j Object, key: &str) -> Option<&'j CJson> {
    object.get(key).filter(|value| value.truthy())
}

/// `convert_period`: an ISO 8601 duration as the shorthand rules use
/// (`PT1H` as `1h`).
fn convert_period(period: &str) -> String {
    let period = period.strip_prefix("PT").unwrap_or(period);
    let period = period.strip_prefix('P').unwrap_or(period);
    period.to_lowercase()
}

/// `_scalar`: `value` as a one-line YAML scalar that reads back as the same
/// text, written by serde-saphyr (#834): plain where that is safe, quoted
/// otherwise. A value of several lines is a JSON string, which YAML reads as
/// a double-quoted scalar, as the oracle wrote it.
pub(crate) fn scalar(value: &CJson) -> String {
    let text = json_text(value);
    if !text.contains('\n') {
        let options = serde_saphyr::ser_options! {
            indent_step: 2,
            compact_list_indent: false,
            folded_wrap_chars: usize::MAX,
            min_fold_chars: usize::MAX,
        };
        if let Ok(written) = serde_saphyr::to_string_with_options(&text, options) {
            let written = written.strip_suffix('\n').unwrap_or(&written);
            if !written.contains('\n') {
                return written.to_owned();
            }
        }
    }
    json_string(&text)
}

/// `_block_style`: `|`, or `|2` when the first non-blank line starts with a
/// space, which YAML would otherwise read as the block's indentation.
fn block_style(text: &str) -> &'static str {
    let first = text
        .split('\n')
        .find(|line| !strip(line).is_empty())
        .unwrap_or("");
    if first.starts_with(' ') { "|2" } else { "|" }
}

/// `_list_items`: a block sequence's lines, each on a new line at `indent`.
fn list_items(values: &[CJson], indent: &str) -> String {
    let mut out = String::new();
    for value in values {
        out.push('\n');
        out.push_str(indent);
        out.push_str("- ");
        out.push_str(&scalar(value));
    }
    out
}

/// The items of a list value (`rule.get(key) or []`); a value that is not a
/// list fails where the oracle iterated it as one.
fn items(object: &Object, key: &str) -> Result<Vec<CJson>, String> {
    match object.get(key) {
        Some(CJson::Array(items)) => Ok(items.clone()),
        Some(value) if !value.truthy() => Ok(Vec::new()),
        None => Ok(Vec::new()),
        Some(CJson::Str(text)) => Ok(text.chars().map(|c| CJson::Str(c.to_string())).collect()),
        Some(other) => Err(format!(
            "TypeError: '{}' object is not iterable",
            type_name(other)
        )),
    }
}

/// `_alert_techniques`: each sub-technique in place of its parent, a parent
/// without one kept, an orphan sub-technique after them, each once.
fn alert_techniques(techniques: &[CJson], sub_techniques: &[CJson]) -> Vec<CJson> {
    let text = |value: &CJson| json_text(value);
    let mut result: Vec<CJson> = Vec::new();
    for technique in techniques {
        let parent = text(technique);
        let children: Vec<CJson> = sub_techniques
            .iter()
            .filter(|sub| text(sub).split('.').next() == Some(parent.as_str()))
            .cloned()
            .collect();
        if children.is_empty() {
            result.push(technique.clone());
        } else {
            result.extend(children);
        }
    }
    let extra: Vec<CJson> = sub_techniques
        .iter()
        .filter(|sub| !result.contains(sub))
        .cloned()
        .collect();
    result.extend(extra);
    let mut unique: Vec<CJson> = Vec::new();
    for item in result {
        if !unique.contains(&item) {
            unique.push(item);
        }
    }
    unique
}

/// The key and column lines of a map (`CUSTOM_DETAILS`), one pair a key.
fn key_columns(value: &CJson) -> Result<String, String> {
    let CJson::Object(object) = value else {
        return Err(no_attribute(value, "items"));
    };
    Ok(object
        .iter()
        .map(|(key, column)| {
            format(
                CUSTOM_DETAILS,
                &[
                    ("key", &scalar(&CJson::Str(key.clone()))),
                    ("column", &scalar(column)),
                ],
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

/// `"\n<indent>".join(text.split("\n"))`.
fn indent_lines(text: &str, indent: &str) -> String {
    text.split('\n')
        .collect::<Vec<_>>()
        .join(&format!("\n{indent}"))
}

/// A listed rule as the importer writes it: its display name (with the
/// tenant's), its file's text, or `None` for a kind it does not import (only
/// scheduled and near-real-time rules are).
#[expect(
    clippy::too_many_lines,
    reason = "the oracle's loop body, block by block, in one place"
)]
pub(crate) fn render(rule: &Object, tenant_name: &str) -> Result<Option<(String, String)>, String> {
    let tenant_scalar = scalar(&CJson::Str(tenant_name.to_owned()));
    let status = if rule.get("enabled") == Some(&CJson::Bool(true)) {
        "PRODUCTION"
    } else {
        "DISABLED"
    };
    let kind = rule.get("kind");
    let (trigger, scheduling) = if kind.map_or_else(String::new, json_text).to_uppercase() == "NRT"
    {
        (TRIGGER_TEMPLATE.to_owned(), NRT_SCHEDULING.to_owned())
    } else if kind == Some(&CJson::Str("Scheduled".into())) {
        let operator = scalar(required(rule, "trigger_operator")?);
        let threshold = json_text(required(rule, "trigger_threshold")?);
        let frequency = convert_period(required_text(rule, "query_frequency", "removeprefix")?);
        let lookback = convert_period(required_text(rule, "query_period", "removeprefix")?);
        (
            format(
                TRIGGER,
                &[("operator", &operator), ("threshold", &threshold)],
            ),
            format(
                SCHEDULING,
                &[("frequency", &frequency), ("lookback", &lookback)],
            ),
        )
    } else {
        return Ok(None);
    };
    let create_incident = mapping(rule, "incident_configuration")?
        .and_then(|incident| incident.get("create_incident"))
        .map_or_else(|| "false".to_owned(), json_text);
    let alert_suppression = if rule.get("suppression_enabled").is_none()
        || rule.get("suppression_enabled") == Some(&CJson::Bool(false))
    {
        "false".to_owned()
    } else {
        convert_period(required_text(rule, "suppression_duration", "removeprefix")?)
    };

    let (custom_details_commented, custom_details) = match truthy(rule, "custom_details") {
        Some(details) => ("", key_columns(details)?),
        None => ("#", CUSTOM_DETAILS_TEMPLATE.to_owned()),
    };
    // The oracle also marked this block commented or not here; every branch
    // below sets the mark again, so only the lines carry over.
    let mut dynamic_properties = match truthy(rule, "dynamic_properties") {
        Some(properties) => key_columns(properties)?,
        None => DYNAMIC_PROPERTIES_TEMPLATE.to_owned(),
    };
    let dynamic_properties_commented;

    let alert_title_commented;
    let alert_title_override;
    let alert_description_commented;
    let alert_description_override;
    let alert_description_style;
    match truthy(rule, "alert_details_override") {
        None => {
            alert_title_commented = "#";
            alert_description_commented = "#";
            alert_title_override = String::new();
            alert_description_override = "#...".to_owned();
            alert_description_style = "|";
            dynamic_properties_commented = "#";
        }
        Some(details) => {
            let CJson::Object(details) = details else {
                return Err(no_attribute(details, "get"));
            };
            if let Some(title) = truthy(details, "alert_display_name_format") {
                alert_title_commented = "";
                alert_title_override = scalar(title);
            } else {
                alert_title_commented = "#";
                alert_title_override = String::new();
            }
            if let Some(description) = truthy(details, "alert_description_format") {
                let CJson::Str(description) = description else {
                    return Err(no_attribute(description, "split"));
                };
                alert_description_commented = "";
                alert_description_style = block_style(description);
                alert_description_override = indent_lines(description, "      ");
            } else {
                alert_description_commented = "#";
                alert_description_style = "|";
                alert_description_override = "#...".to_owned();
            }
            if let Some(properties) = truthy(details, "alert_dynamic_properties") {
                let CJson::Array(properties) = properties else {
                    return Err(format!(
                        "TypeError: '{}' object is not iterable",
                        type_name(properties)
                    ));
                };
                dynamic_properties_commented = "";
                dynamic_properties = String::new();
                for property in properties {
                    let CJson::Object(property) = property else {
                        return Err(format!(
                            "TypeError: '{}' object is not subscriptable",
                            type_name(property)
                        ));
                    };
                    dynamic_properties.push('\n');
                    dynamic_properties.push_str(&format(
                        DYNAMIC_PROPERTIES,
                        &[
                            ("property", &scalar(required(property, "alert_property")?)),
                            ("column", &scalar(required(property, "value")?)),
                        ],
                    ));
                }
            } else {
                dynamic_properties_commented = "#";
                DYNAMIC_PROPERTIES_TEMPLATE.clone_into(&mut dynamic_properties);
            }
        }
    }

    let tactics = match truthy(rule, "tactics") {
        Some(_) => format!("tactics:{}", list_items(&items(rule, "tactics")?, "      ")),
        None => REMOVE.to_owned(),
    };
    let techniques = alert_techniques(&items(rule, "techniques")?, &items(rule, "sub_techniques")?);
    let techniques = if techniques.is_empty() {
        REMOVE.to_owned()
    } else {
        format!("techniques:{}", list_items(&techniques, "      "))
    };

    let event_aggregation = scalar(
        mapping(rule, "event_grouping_settings")?
            .and_then(|settings| settings.get("aggregation_kind"))
            .filter(|kind| kind.truthy())
            .unwrap_or(&CJson::Str("SingleAlert".into())),
    );
    let empty = Object::new();
    let incident = mapping_or_empty(rule, "incident_configuration")?.unwrap_or(&empty);
    let grouping = mapping_or_empty(incident, "grouping_configuration")?.unwrap_or(&empty);
    let (
        alert_grouping_enabled,
        reopen_closed_incidents_commented,
        reopen_closed_incidents,
        grouping_configuration,
    ) = if required(grouping, "enabled")? == &CJson::Bool(false) {
        ("false", "#", String::new(), String::new())
    } else {
        let reopen = grouping
            .get("reopen_closed_incident")
            .map_or_else(|| "false".to_owned(), json_text);
        let lookback = convert_period(required_text(
            grouping,
            "lookback_duration",
            "removeprefix",
        )?);
        let matching = scalar(required(grouping, "matching_method")?);
        let group = |key: &str, label: &str| -> Result<String, String> {
            Ok(match truthy(grouping, key) {
                Some(_) => format!("{label}:{}", list_items(&items(grouping, key)?, "        ")),
                None => REMOVE.to_owned(),
            })
        };
        let configuration = format(
            GROUPING_CONFIGURATION,
            &[
                ("grouping_lookback", &lookback),
                ("grouping_matching_method", &matching),
                (
                    "group_by_entities",
                    &group("group_by_entities", "group_by_entities")?,
                ),
                (
                    "group_by_alert_details",
                    &group("group_by_alert_details", "group_by_alert_details")?,
                ),
                (
                    "group_by_custom_details",
                    &group("group_by_custom_details", "group_by_custom_details")?,
                ),
            ],
        );
        (
            "true",
            "",
            reopen,
            configuration.trim_matches('\n').to_owned(),
        )
    };

    let (entities_commented, entities) = match truthy(rule, "entity_mappings") {
        Some(mappings) => {
            let CJson::Array(mappings) = mappings else {
                return Err(format!(
                    "TypeError: '{}' object is not iterable",
                    type_name(mappings)
                ));
            };
            let mut entities = Vec::new();
            for entity in mappings {
                let CJson::Object(entity) = entity else {
                    return Err(format!(
                        "TypeError: '{}' object is not subscriptable",
                        type_name(entity)
                    ));
                };
                let mut lines = Vec::new();
                let fields = required(entity, "field_mappings")?;
                let CJson::Array(fields) = fields else {
                    return Err(format!(
                        "TypeError: '{}' object is not iterable",
                        type_name(fields)
                    ));
                };
                for field in fields {
                    let CJson::Object(field) = field else {
                        return Err(format!(
                            "TypeError: '{}' object is not subscriptable",
                            type_name(field)
                        ));
                    };
                    lines.push(format(
                        ENTITIES_MAPPINGS,
                        &[
                            ("identifier", &scalar(required(field, "identifier")?)),
                            ("column", &scalar(required(field, "column_name")?)),
                        ],
                    ));
                }
                entities.push(format(
                    ENTITIES,
                    &[
                        ("entity", &scalar(required(entity, "entity_type")?)),
                        ("mappings", &lines.join("\n")),
                    ],
                ));
            }
            ("", entities.join("\n"))
        }
        None => ("#", ENTITIES_TEMPLATE.to_owned()),
    };

    let query = required_text(rule, "query", "split")?;
    let block = format(
        BLOCK,
        &[
            ("status", status),
            ("tenant_name", &tenant_scalar),
            ("trigger", &trigger),
            ("scheduling", &scheduling),
            ("create_incident", &create_incident),
            ("alert_suppression", &alert_suppression),
            ("alert_title_commented", alert_title_commented),
            ("alert_title_override", &alert_title_override),
            ("alert_description_commented", alert_description_commented),
            ("alert_description_style", alert_description_style),
            ("alert_description_override", &alert_description_override),
            ("custom_details_commented", custom_details_commented),
            ("custom_details", &custom_details),
            ("dynamic_properties_commented", dynamic_properties_commented),
            ("dynamic_properties", &dynamic_properties),
            ("tactics", &tactics),
            ("techniques", &techniques),
            ("event_aggregation", &event_aggregation),
            ("alert_grouping_enabled", alert_grouping_enabled),
            (
                "reopen_closed_incidents_commented",
                reopen_closed_incidents_commented,
            ),
            ("reopen_closed_incidents", &reopen_closed_incidents),
            ("grouping_configuration", &grouping_configuration),
            ("entities_commented", entities_commented),
            ("entities", &entities),
            ("query_style", block_style(query)),
            ("query", &indent_lines(query, "    ")),
        ],
    );
    let block = indent_lines(&block, "  ");
    let block = block.trim_matches('\n');

    let display_name = match required(rule, "display_name")? {
        CJson::Str(name) => format!("{name} - {tenant_name}"),
        other => {
            return Err(format!(
                "TypeError: unsupported operand type(s) for +: '{}' and 'str'",
                type_name(other)
            ));
        }
    };
    let description = required_text(rule, "description", "split")?;
    let created = required_text(rule, "last_modified_utc", "split")?
        .split('T')
        .next()
        .unwrap_or_default()
        .to_owned();
    let text = format(
        MDR,
        &[
            ("rule_name", &json_string(&display_name)),
            ("rule_uuid", &scalar(required(rule, "name")?)),
            ("rule_creation", &created),
            ("rule_modified", &created),
            ("rule_author", "opentide Sentinel Importer"),
            ("rule_description_style", block_style(description)),
            ("rule_description", &indent_lines(description, "  ")),
            ("rule_severity", &scalar(required(rule, "severity")?)),
            ("sentinel", block),
        ],
    );
    let text = text
        .trim_matches('\n')
        .split('\n')
        .filter(|line| !line.contains(REMOVE))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Some((display_name, text)))
}

// ------------------------------------------------------------------ the run

/// `opentide generate extract sentinel` (`sentinel_importer.run`).
pub fn sentinel(cx: &Context<'_>) -> super::Report {
    sentinel_with(cx, &Sentinel::new())
}

/// The run on `connector`: a test fixes its request ids.
pub fn sentinel_with(cx: &Context<'_>, connector: &Sentinel) -> super::Report {
    let started = Instant::now();
    let mut written = 0;
    let outcome = run(cx, connector, &mut written);
    report(SENTINEL, started, written, outcome)
}

fn run(cx: &Context<'_>, connector: &Sentinel, written_count: &mut usize) -> Outcome {
    let (tenants, root) = configured(cx, SENTINEL)?;
    super::super::query::log_unset(&tenants, cx.env);
    if tenants.is_empty() {
        tracing::error!(
            detail = "You must first have Sentinel tenants configured to initiate the import",
            advice = "run 'opentide setup platforms --sentinel'",
            logger = LOGGER,
            critical = true,
            "sentinel_tenants_not_configured"
        );
        return Err("No Sentinel tenants are configured".into());
    }
    let environment = Environment::from_pairs(cx.env.iter());
    // Display names are not unique in Sentinel; never overwrite a file from this run.
    let mut written: Vec<String> = Vec::new();
    for configured in &tenants {
        let (tenant, http) = tenant(
            SENTINEL,
            configured,
            Duration::from_secs(60),
            &environment,
            cx.proxy,
        )?;
        let rules = block_on(async {
            let cancel = CancellationToken::new();
            let context = TenantContext {
                tenant: &tenant,
                http: &http,
                cancel: &cancel,
            };
            connector.list(context).await
        })?
        .map_err(|error| failure(&error))?
        .map_err(|error| error.to_string())?;
        let rules: Vec<CJson> = rules.iter().map(flat_rule).collect();
        let dump = cx.cwd.join(format!("output-{}.json", configured.name));
        write_text(&dump, &json_indent4(&CJson::Array(rules.clone())))?;
        for rule in &rules {
            let CJson::Object(rule) = rule else {
                return Err(no_attribute(rule, "get"));
            };
            let Some((display_name, text)) = render(rule, &configured.name)? else {
                continue;
            };
            if let Err(error) = opentide_schema::node::load(&text) {
                let first = format!("{error}");
                let first = first.lines().next().unwrap_or_default();
                tracing::error!(
                    rule = display_name.as_str(),
                    reason = format!("would write invalid YAML: {first}").as_str(),
                    logger = LOGGER,
                    "sentinel_import_rule_skipped"
                );
                continue;
            }
            let mut stem = sanitize_filename(&format!("\"{display_name}\""));
            if written.contains(&stem.to_lowercase()) {
                let id: String = rule
                    .get("name")
                    .map(json_text)
                    .unwrap_or_default()
                    .chars()
                    .take(8)
                    .collect();
                stem = format!("{stem} {id}");
            }
            written.push(stem.to_lowercase());
            let destination = cx.cwd.join("Imported");
            std::fs::create_dir_all(&destination)
                .map_err(|error| format!("{}: {error}", destination.display()))?;
            let path = destination.join(format!("{stem}.yaml"));
            write_text(&path, &text)?;
            if under(&path, &root) {
                *written_count += 1;
            }
        }
    }
    Ok(Vec::new())
}

/// A failure before ARM answered, as the importer's exception reads.
fn failure(error: &ConnectorError) -> String {
    match error {
        ConnectorError::Authentication { message, .. } => {
            format!("ClientAuthenticationError: {message}")
        }
        other => super::connector_message(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> CJson {
        serde_json::from_str(text).unwrap()
    }

    fn object(text: &str) -> Object {
        match flat_rule(&json(text)) {
            CJson::Object(object) => object,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_listed_rule_is_flat_and_snake_case_but_its_custom_details() {
        let rule = flat_rule(&json(
            r#"{"kind": "Scheduled", "name": "n", "properties": {"displayName": "D",
                "customDetails": {"HostName": "Computer"}, "kind": "NRT",
                "entityMappings": [{"entityType": "Host", "fieldMappings": [{"columnName": "C"}]}]}}"#,
        ));
        assert_eq!(
            rule.to_compact(),
            r#"{"kind":"NRT","name":"n","display_name":"D","custom_details":{"HostName":"Computer"},"entity_mappings":[{"entity_type":"Host","field_mappings":[{"column_name":"C"}]}]}"#
        );
        assert_eq!(snake_case("subTechniques"), "sub_techniques");
        assert_eq!(snake_case("ID"), "i_d");
        assert_eq!(snake_case("Name"), "name");
    }

    #[test]
    fn the_dump_is_indented_four_spaces() {
        let value = json(r#"[{"a": [], "b": {}, "c": [1, true, null], "d": "é—\"", "e": 1.5}]"#);
        assert_eq!(
            json_indent4(&value),
            "[\n    {\n        \"a\": [],\n        \"b\": {},\n        \"c\": [\n            1,\n            true,\n            null\n        ],\n        \"d\": \"é—\\\"\",\n        \"e\": 1.5\n    }\n]\n"
        );
        assert_eq!(json_indent4(&CJson::Array(Vec::new())), "[]\n");
    }

    #[test]
    fn a_scalar_is_written_by_serde_saphyr_on_one_line() {
        let text = |value: &str| scalar(&CJson::Str(value.into()));
        assert_eq!(text("Process"), "Process");
        assert_eq!(text("{{Computer}} ran"), "\"{{Computer}} ran\"");
        assert_eq!(text("a: b"), "\"a: b\"");
        assert_eq!(text(""), "\"\"");
        assert_eq!(text("yes"), "\"yes\"");
        assert_eq!(text("Ünïcode — ok"), "Ünïcode — ok");
        assert_eq!(text("two\nlines"), "\"two\\nlines\"");
        assert_eq!(scalar(&CJson::Int(5)), "\"5\"");
        assert_eq!(scalar(&CJson::Bool(true)), "\"true\"");
        let long = "x ".repeat(200);
        assert!(!scalar(&CJson::Str(long)).contains('\n'));
    }

    #[test]
    fn periods_blocks_and_techniques_are_the_importers() {
        assert_eq!(convert_period("PT1H"), "1h");
        assert_eq!(convert_period("P1D"), "1d");
        assert_eq!(convert_period("PT30M"), "30m");
        assert_eq!(block_style("a\nb"), "|");
        assert_eq!(block_style("\n  a"), "|2");
        let ids = |items: &[&str]| -> Vec<CJson> {
            items
                .iter()
                .map(|item| CJson::Str((*item).into()))
                .collect()
        };
        assert_eq!(
            alert_techniques(
                &ids(&["T1059", "T1027"]),
                &ids(&["T1059.001", "T1564.003", "T1059.001"])
            ),
            ids(&["T1059.001", "T1027", "T1564.003"])
        );
        assert!(alert_techniques(&[], &[]).is_empty());
    }

    const RULE: &str = r#"{"kind": "Scheduled", "name": "00000000-0000-4000-8044-0000000000aa",
        "properties": {"displayName": "Rule", "description": "D", "severity": "High",
        "enabled": true, "query": "T", "queryFrequency": "PT1H", "queryPeriod": "PT1H",
        "triggerOperator": "GreaterThan", "triggerThreshold": 0,
        "incidentConfiguration": {"createIncident": true,
            "groupingConfiguration": {"enabled": false}},
        "lastModifiedUtc": "2026-01-02T03:04:05Z"}}"#;

    #[test]
    fn a_rule_renders_to_a_file_that_loads() {
        let (name, text) = render(&object(RULE), "soc").unwrap().unwrap();
        assert_eq!(name, "Rule - soc");
        assert!(text.starts_with("name: \"Rule - soc\"\n"), "{text}");
        assert!(text.contains("\n  created: 2026-01-02\n"), "{text}");
        assert!(!text.contains(REMOVE));
        opentide_schema::node::load(&text).unwrap();
        // A Fusion rule is not imported.
        let fusion = RULE.replace("\"Scheduled\"", "\"Fusion\"");
        assert!(render(&object(&fusion), "soc").unwrap().is_none());
    }

    #[test]
    fn a_missing_or_mistyped_field_fails_as_the_importer_did() {
        let failed =
            |from: &str, to: &str| render(&object(&RULE.replace(from, to)), "soc").unwrap_err();
        assert_eq!(
            failed("\"triggerOperator\": \"GreaterThan\",", ""),
            "KeyError: 'trigger_operator'"
        );
        assert_eq!(failed("{\"enabled\": false}", "{}"), "KeyError: 'enabled'");
        assert_eq!(
            failed("\"queryPeriod\": \"PT1H\"", "\"queryPeriod\": 3"),
            "AttributeError: 'int' object has no attribute 'removeprefix'"
        );
        assert_eq!(
            failed(
                "\"incidentConfiguration\": {\"createIncident\": true,",
                "\"incidentConfiguration\": [], \"x\": {\"createIncident\": true,"
            ),
            "AttributeError: 'list' object has no attribute 'get'"
        );
    }
}
