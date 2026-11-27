//! `opentide generate extract sentinel` (UC-4.4e, #834;
//! `extraction/sentinel_importer.py`): the analytics rules of each Sentinel
//! tenant, listed through the connectors' ARM client
//! ([`opentide_connectors::sentinel::Sentinel::list`]), and written as
//! opentide rule files under `Imported/`.
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
use opentide_connectors::Environment;
use opentide_connectors::connector::TenantContext;
use opentide_connectors::sentinel::Sentinel;
use opentide_connectors::text::json_text;
use tokio_util::sync::CancellationToken;

use super::{
    Context, FieldError, Outcome, Skipped, block_on, configured, fill, json_string, report,
    sanitize_filename, tenant, under, write_text,
};

const SENTINEL: &str = "sentinel";
/// A line that is only this is left out of a file (`OPENTIDE::REMOVE`).
/// The control characters around it are ones no value can bring in: a
/// scalar escapes them and [`block_text`] refuses them, so a rule whose
/// text says `OPENTIDE::REMOVE` loses no line.
const REMOVE: &str = "\u{1}OPENTIDE::REMOVE\u{1}";

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
const RULE_TEMPLATE: &str = "\nname: {rule_name}\n\n#references:\n  #public:\n    #1: \n  #internal:\n    #a: \n\nmetadata:\n  uuid: {rule_uuid}\n  schema: rule::1.0\n  version: \n  created: {rule_creation}\n  modified: {rule_modified}\n  tlp: amber\n  author: {rule_author} \n  #contributors:\n    #-\n\ndescription: {rule_description_style}\n  {rule_description}\n#detection_model: \n\nresponse:\n  alert_severity: {rule_severity}\n  #playbook: https://\n  #responders: \n  #procedure:\n    #analysis: |\n      #...\n    #searches:\n      #- purpose: |\n          #...\n        #system: \n        #query: |\n          #...\n    #containment: |\n      #...\n\nconfigurations:\n  sentinel: \n{sentinel}\n";
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

// ------------------------------------------------------ reading a listed rule

/// The mapping at `key`: none when it is missing, `null` or empty.
fn mapping<'j>(object: &'j Object, key: &str) -> Result<Option<&'j Object>, FieldError> {
    match object.get(key) {
        None | Some(CJson::Null) => Ok(None),
        Some(CJson::Object(inner)) if inner.is_empty() => Ok(None),
        Some(CJson::Object(inner)) => Ok(Some(inner)),
        Some(_) => Err(FieldError::not(key, "a mapping")),
    }
}

/// The value at `key`, which must be there and not `null`.
fn required<'j>(object: &'j Object, key: &str) -> Result<&'j CJson, FieldError> {
    object
        .get(key)
        .filter(|value| !value.is_null())
        .ok_or_else(|| FieldError::missing(key))
}

/// The string at `key`, which must be there.
fn required_text<'j>(object: &'j Object, key: &str) -> Result<&'j str, FieldError> {
    required(object, key)?
        .as_str()
        .ok_or_else(|| FieldError::not(key, "a string"))
}

/// The value at `key` when ARM set it: not missing, `null`, `false`, nor an
/// empty string, list or object, each of which leaves a block commented out.
fn given<'j>(object: &'j Object, key: &str) -> Option<&'j CJson> {
    object.get(key).filter(|value| match value {
        CJson::Null | CJson::Bool(false) => false,
        CJson::Str(text) => !text.is_empty(),
        CJson::Array(items) => !items.is_empty(),
        CJson::Object(members) => !members.is_empty(),
        CJson::Bool(true) | CJson::Int(_) | CJson::UInt(_) | CJson::Float(_) => true,
    })
}

/// The objects of the list at `key` (`shown` in an error).
fn objects<'j>(value: &'j CJson, shown: &str) -> Result<Vec<&'j Object>, FieldError> {
    let CJson::Array(items) = value else {
        return Err(FieldError::not(shown, "a list"));
    };
    items
        .iter()
        .map(|item| match item {
            CJson::Object(object) => Ok(object),
            _ => Err(FieldError::not(shown, "a list of mappings")),
        })
        .collect()
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

/// `text` as the content of a YAML block scalar (`|`): every line break
/// YAML knows (CR, CRLF, NEL, U+2028, U+2029) an LF, so a lone `\r` cannot
/// end the block and start a key of its own. A character YAML does not
/// allow in a file (a control character, U+FFFE) cannot be written in a
/// block: the rule is not imported, and `field` names why.
pub(crate) fn block_text(text: &str, field: &str) -> Result<String, FieldError> {
    // Every YAML line break: wider than `opentide_core::text::universal_newlines`.
    let text = text
        .replace("\r\n", "\n")
        .replace(['\r', '\u{85}', '\u{2028}', '\u{2029}'], "\n");
    let printable = |c: char| {
        matches!(c, '\t' | '\n' | '\u{20}'..='\u{7e}' | '\u{a0}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}')
            || c >= '\u{10000}'
    };
    if text.chars().all(printable) {
        Ok(text)
    } else {
        Err(FieldError::not(field, "text without control characters"))
    }
}

/// A boolean or a number as YAML writes it; any other value as [`scalar`]
/// writes it, so a string cannot break the line it is on.
fn literal(value: &CJson) -> String {
    match value {
        CJson::Bool(_) | CJson::Int(_) | CJson::UInt(_) | CJson::Float(_) => json_text(value),
        _ => scalar(value),
    }
}

/// A date as the importer writes it: `YYYY-MM-DD` bare, as the oracle wrote
/// it; anything else as [`scalar`] writes it, so it cannot break the line.
pub(crate) fn date_scalar(text: &str) -> String {
    let bytes = text.as_bytes();
    let is_date = bytes.len() == 10
        && bytes.iter().enumerate().all(|(at, byte)| match at {
            4 | 7 => *byte == b'-',
            _ => byte.is_ascii_digit(),
        });
    if is_date {
        text.to_owned()
    } else {
        scalar(&CJson::Str(text.to_owned()))
    }
}

/// [`convert_period`]'s duration as a YAML scalar ([`scalar`]).
fn period(text: &str) -> String {
    scalar(&CJson::Str(convert_period(text)))
}

/// `_block_style`: `|`, or `|2` when the first non-blank line starts with a
/// space, which YAML would otherwise read as the block's indentation.
fn block_style(text: &str) -> &'static str {
    let first = text
        .split('\n')
        .find(|line| !line.trim().is_empty())
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

/// The items of a list value: none when it is missing, `null` or an empty
/// string, and a single string as its one item, never its characters.
fn items(object: &Object, key: &str) -> Result<Vec<CJson>, FieldError> {
    match object.get(key) {
        Some(CJson::Array(items)) => Ok(items.clone()),
        None | Some(CJson::Null) => Ok(Vec::new()),
        Some(CJson::Str(text)) if text.is_empty() => Ok(Vec::new()),
        Some(text @ CJson::Str(_)) => Ok(vec![text.clone()]),
        Some(_) => Err(FieldError::not(key, "a list")),
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
fn key_columns(value: &CJson, key: &str) -> Result<String, FieldError> {
    let CJson::Object(object) = value else {
        return Err(FieldError::not(key, "a mapping"));
    };
    Ok(object
        .iter()
        .map(|(key, column)| {
            fill(
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
pub(crate) fn render(
    rule: &Object,
    tenant_name: &str,
) -> Result<Option<(String, String)>, FieldError> {
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
        let threshold = literal(required(rule, "trigger_threshold")?);
        let frequency = period(required_text(rule, "query_frequency")?);
        let lookback = period(required_text(rule, "query_period")?);
        (
            fill(
                TRIGGER,
                &[("operator", &operator), ("threshold", &threshold)],
            ),
            fill(
                SCHEDULING,
                &[("frequency", &frequency), ("lookback", &lookback)],
            ),
        )
    } else {
        return Ok(None);
    };
    let create_incident = mapping(rule, "incident_configuration")?
        .and_then(|incident| incident.get("create_incident"))
        .map_or_else(|| "false".to_owned(), literal);
    let alert_suppression = if rule.get("suppression_enabled").is_none()
        || rule.get("suppression_enabled") == Some(&CJson::Bool(false))
    {
        "false".to_owned()
    } else {
        period(required_text(rule, "suppression_duration")?)
    };

    let (custom_details_commented, custom_details) = match given(rule, "custom_details") {
        Some(details) => ("", key_columns(details, "custom_details")?),
        None => ("#", CUSTOM_DETAILS_TEMPLATE.to_owned()),
    };
    // The oracle also marked this block commented or not here; every branch
    // below sets the mark again, so only the lines carry over.
    let mut dynamic_properties = match given(rule, "dynamic_properties") {
        Some(properties) => key_columns(properties, "dynamic_properties")?,
        None => DYNAMIC_PROPERTIES_TEMPLATE.to_owned(),
    };
    let dynamic_properties_commented;

    let alert_title_commented;
    let alert_title_override;
    let alert_description_commented;
    let alert_description_override;
    let alert_description_style;
    match given(rule, "alert_details_override") {
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
                return Err(FieldError::not("alert_details_override", "a mapping"));
            };
            if let Some(title) = given(details, "alert_display_name_format") {
                alert_title_commented = "";
                alert_title_override = scalar(title);
            } else {
                alert_title_commented = "#";
                alert_title_override = String::new();
            }
            if let Some(description) = given(details, "alert_description_format") {
                let CJson::Str(description) = description else {
                    return Err(FieldError::not(
                        "alert_details_override.alert_description_format",
                        "a string",
                    ));
                };
                let description = &block_text(
                    description,
                    "alert_details_override.alert_description_format",
                )?;
                alert_description_commented = "";
                alert_description_style = block_style(description);
                alert_description_override = indent_lines(description, "      ");
            } else {
                alert_description_commented = "#";
                alert_description_style = "|";
                alert_description_override = "#...".to_owned();
            }
            if let Some(properties) = given(details, "alert_dynamic_properties") {
                const SHOWN: &str = "alert_details_override.alert_dynamic_properties";
                let in_list = |error: FieldError| error.under(SHOWN);
                dynamic_properties_commented = "";
                dynamic_properties = String::new();
                for property in objects(properties, SHOWN)? {
                    dynamic_properties.push('\n');
                    dynamic_properties.push_str(&fill(
                        DYNAMIC_PROPERTIES,
                        &[
                            (
                                "property",
                                &scalar(required(property, "alert_property").map_err(in_list)?),
                            ),
                            (
                                "column",
                                &scalar(required(property, "value").map_err(in_list)?),
                            ),
                        ],
                    ));
                }
            } else {
                dynamic_properties_commented = "#";
                DYNAMIC_PROPERTIES_TEMPLATE.clone_into(&mut dynamic_properties);
            }
        }
    }

    let tactics = match given(rule, "tactics") {
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
            .filter(|kind| kind.as_str().is_some_and(|kind| !kind.is_empty()))
            .unwrap_or(&CJson::Str("SingleAlert".into())),
    );
    let empty = Object::new();
    let incident = mapping(rule, "incident_configuration")?.unwrap_or(&empty);
    let grouping = mapping(incident, "grouping_configuration")
        .map_err(|error| error.under("incident_configuration"))?
        .unwrap_or(&empty);
    let in_grouping =
        |error: FieldError| error.under("incident_configuration.grouping_configuration");
    let (
        alert_grouping_enabled,
        reopen_closed_incidents_commented,
        reopen_closed_incidents,
        grouping_configuration,
    ) = if required(grouping, "enabled").map_err(in_grouping)? == &CJson::Bool(false) {
        ("false", "#", String::new(), String::new())
    } else {
        let reopen = grouping
            .get("reopen_closed_incident")
            .map_or_else(|| "false".to_owned(), literal);
        let lookback = period(required_text(grouping, "lookback_duration").map_err(in_grouping)?);
        let matching = scalar(required(grouping, "matching_method").map_err(in_grouping)?);
        let group = |key: &str, label: &str| -> Result<String, FieldError> {
            Ok(match given(grouping, key) {
                Some(_) => format!("{label}:{}", list_items(&items(grouping, key)?, "        ")),
                None => REMOVE.to_owned(),
            })
        };
        let configuration = fill(
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

    let (entities_commented, entities) = match given(rule, "entity_mappings") {
        Some(mappings) => {
            const SHOWN: &str = "entity_mappings";
            const FIELDS: &str = "entity_mappings.field_mappings";
            let in_list = |error: FieldError| error.under(SHOWN);
            let in_fields = |error: FieldError| error.under(FIELDS);
            let mut entities = Vec::new();
            for entity in objects(mappings, SHOWN)? {
                let mut lines = Vec::new();
                let fields = required(entity, "field_mappings").map_err(in_list)?;
                for field in objects(fields, FIELDS)? {
                    lines.push(fill(
                        ENTITIES_MAPPINGS,
                        &[
                            (
                                "identifier",
                                &scalar(required(field, "identifier").map_err(in_fields)?),
                            ),
                            (
                                "column",
                                &scalar(required(field, "column_name").map_err(in_fields)?),
                            ),
                        ],
                    ));
                }
                entities.push(fill(
                    ENTITIES,
                    &[
                        (
                            "entity",
                            &scalar(required(entity, "entity_type").map_err(in_list)?),
                        ),
                        ("mappings", &lines.join("\n")),
                    ],
                ));
            }
            ("", entities.join("\n"))
        }
        None => ("#", ENTITIES_TEMPLATE.to_owned()),
    };

    let query = &block_text(required_text(rule, "query")?, "query")?;
    let block = fill(
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

    let display_name = format!("{} - {tenant_name}", required_text(rule, "display_name")?);
    let description = &block_text(required_text(rule, "description")?, "description")?;
    let created = required_text(rule, "last_modified_utc")?
        .split('T')
        .next()
        .unwrap_or_default()
        .to_owned();
    let text = fill(
        RULE_TEMPLATE,
        &[
            (
                "rule_name",
                &opentide_schema::node::double_quoted(&display_name),
            ),
            ("rule_uuid", &scalar(required(rule, "name")?)),
            ("rule_creation", &date_scalar(&created)),
            ("rule_modified", &date_scalar(&created)),
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
        .filter(|line| line.trim() != REMOVE)
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
    if let Some(refused) = super::config_refusal(SENTINEL, cx) {
        return refused;
    }
    let started = Instant::now();
    let mut written = 0;
    let outcome = run(cx, connector, &mut written);
    report(SENTINEL, started, written, outcome)
}

fn run(cx: &Context<'_>, connector: &Sentinel, written_count: &mut usize) -> Outcome {
    let (tenants, root) = configured(cx, SENTINEL)?;
    super::super::query::log_unset(&tenants, cx.env, "an extract");
    if tenants.is_empty() {
        tracing::error!(
            detail = "You must first have Sentinel tenants configured to initiate the import",
            advice = "run 'opentide setup platforms --sentinel'",
            critical = true,
            "sentinel_tenants_not_configured"
        );
        return Err("No Sentinel tenants are configured".into());
    }
    let environment = Environment::from_pairs(cx.env.iter());
    // Display names are not unique in Sentinel; never overwrite a file from this run.
    let mut written: Vec<String> = Vec::new();
    let mut skipped = Skipped::new("sentinel_import_rule_skipped");
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
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
        let rules: Vec<CJson> = rules.iter().map(flat_rule).collect();
        for rule in &rules {
            let CJson::Object(rule) = rule else {
                skipped.push("", "the listed rule is not a JSON object");
                continue;
            };
            let field = |key: &str| rule.get(key).map(json_text).unwrap_or_default();
            let (display_name, text) = match render(rule, &configured.name) {
                Ok(Some(rendered)) => rendered,
                Ok(None) => continue,
                Err(error) => {
                    let shown = format!("{} - {}", field("display_name"), configured.name);
                    skipped.push(&shown, &format!("rule {}: {error}", field("name")));
                    continue;
                }
            };
            if let Err(error) = opentide_schema::node::load(&text) {
                let first = format!("{error}");
                let first = first.lines().next().unwrap_or_default();
                skipped.push(&display_name, &format!("would write invalid YAML: {first}"));
                continue;
            }
            let stem = file_stem(&field("display_name"), &configured.name, &field("name"));
            let stem = unique_stem(stem, &field("name"), &written);
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
    Ok(skipped.into_keys())
}

/// The name of a rule's file, without `.yaml`: `<display name> - <tenant>`,
/// the characters a file name cannot hold as spaces and no space at either
/// end. A blank display name falls back to the rule's id, so a file is never
/// named `.yaml` (hidden) or ` - soc.yaml`.
fn file_stem(display_name: &str, tenant: &str, id: &str) -> String {
    let blank = |text: &str| sanitize_filename(text).trim().is_empty();
    let name = [display_name, id].into_iter().find(|text| !blank(text));
    let parts: Vec<&str> = name
        .into_iter()
        .chain((!blank(tenant)).then_some(tenant))
        .collect();
    let stem = sanitize_filename(&parts.join(" - ")).trim().to_owned();
    if stem.is_empty() {
        "rule".to_owned()
    } else {
        stem
    }
}

/// `stem`, or, when a file of this run already has that name (compared
/// without case: display names are not unique in Sentinel), `stem` followed
/// by the first eight characters of the rule's id, or by a counter when the
/// id is blank or taken too. Never ends in a space.
fn unique_stem(stem: String, id: &str, taken: &[String]) -> String {
    let free = |candidate: &str| !taken.contains(&candidate.to_lowercase());
    if free(&stem) {
        return stem;
    }
    let short: String = id.chars().take(8).collect();
    let short = sanitize_filename(&short).trim().to_owned();
    if !short.is_empty() {
        let candidate = format!("{stem} {short}");
        if free(&candidate) {
            return candidate;
        }
    }
    // `taken` holds fewer names than this range: one of them is free.
    (2..=taken.len() + 2)
        .map(|n| format!("{stem} {n}"))
        .find(|candidate| free(candidate))
        .unwrap_or(stem)
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

    /// The tenant's values reach the file as YAML scalars: a threshold, a
    /// period or a date that is not what the importer expects cannot break
    /// the file or change what it reads as.
    #[test]
    fn hostile_values_read_back_as_written() {
        let rule = RULE
            .replace(r#""triggerThreshold": 0"#, r#""triggerThreshold": "5 #x""#)
            .replace(
                r#""queryFrequency": "PT1H""#,
                r#""queryFrequency": "PT1H: [x]""#,
            )
            .replace(
                r#""createIncident": true"#,
                r#""createIncident": "yes: no""#,
            )
            .replace("2026-01-02T03:04:05Z", "2026: 01 #x");
        let (_, text) = render(&object(&rule), "soc").unwrap().unwrap();
        let document =
            opentide_schema::node::load(&text).unwrap_or_else(|e| panic!("{e:?}\n{text}"));
        let root = document.root().unwrap();
        let at = |path: &[&str]| -> Option<String> {
            let mut node = root;
            for key in path {
                node = node.get(key)?;
            }
            node.value.as_str().map(str::to_owned)
        };
        assert_eq!(
            at(&["metadata", "created"]).as_deref(),
            Some("2026: 01 #x"),
            "{text}"
        );
        let block = |rest: &[&str]| at(&[&["configurations", "sentinel"][..], rest].concat());
        assert_eq!(
            block(&["trigger", "threshold"]).as_deref(),
            Some("5 #x"),
            "{text}"
        );
        assert_eq!(
            block(&["scheduling", "frequency"]).as_deref(),
            Some("1h: [x]"),
            "{text}"
        );
        assert_eq!(
            block(&["alert", "create_incident"]).as_deref(),
            Some("yes: no"),
            "{text}"
        );
    }

    /// A lone CR in a query or description stays in its block, and a value
    /// that says `OPENTIDE::REMOVE` loses no line.
    #[test]
    fn tenant_text_cannot_end_a_block_or_remove_a_line() {
        let rule = RULE
            .replace(r#""query": "T""#, r#""query": "T\rname: INJECTED""#)
            .replace(
                r#""description": "D""#,
                r#""description": "D\u2028status: X""#,
            )
            .replace(
                r#""displayName": "Rule""#,
                r#""displayName": "Rule OPENTIDE::REMOVE""#,
            );
        let (_, text) = render(&object(&rule), "soc").unwrap().unwrap();
        let document =
            opentide_schema::node::load(&text).unwrap_or_else(|e| panic!("{e:?}\n{text}"));
        let root = document.root().unwrap();
        assert_eq!(
            root.get("name").unwrap().value.as_str(),
            Some("Rule OPENTIDE::REMOVE - soc"),
            "{text}"
        );
        assert!(root.get("status").is_none(), "{text}");
        let query = root
            .get("configurations")
            .and_then(|block| block.get("sentinel"))
            .and_then(|block| block.get("query"))
            .unwrap();
        assert_eq!(query.value.as_str(), Some("T\nname: INJECTED\n"), "{text}");
        let refused = RULE.replace(r#""query": "T""#, r#""query": "T\u0001""#);
        assert_eq!(
            render(&object(&refused), "soc").unwrap_err().to_string(),
            "field `query` is not text without control characters"
        );
    }

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

    /// A blank display name is named after the rule's id, never `.yaml` or
    /// ` - soc.yaml`; no name has a space at either end.
    #[test]
    fn a_file_name_is_never_blank_nor_padded() {
        assert_eq!(file_stem("Rule", "soc", "id"), "Rule - soc");
        assert_eq!(file_stem(" a:b? ", "soc", "id"), "a b   - soc");
        assert_eq!(file_stem("", "soc", "0123"), "0123 - soc");
        assert_eq!(file_stem("  ", "soc", "0123"), "0123 - soc");
        assert_eq!(file_stem("", "", "0123"), "0123");
        assert_eq!(file_stem("Rule", "", "0123"), "Rule");
        assert_eq!(file_stem("", "", ""), "rule");
        assert_eq!(file_stem("?", "*", "/"), "rule");
    }

    /// A second rule of the same name takes the id's first eight
    /// characters; without an id, a counter, never a trailing space.
    #[test]
    fn a_repeated_file_name_takes_a_suffix_without_a_trailing_space() {
        let taken = |names: &[&str]| names.iter().map(|n| n.to_lowercase()).collect::<Vec<_>>();
        assert_eq!(
            unique_stem("R - soc".into(), "0123456789", &taken(&[])),
            "R - soc"
        );
        assert_eq!(
            unique_stem("R - soc".into(), "0123456789", &taken(&["r - soc"])),
            "R - soc 01234567"
        );
        assert_eq!(
            unique_stem("R - soc".into(), "", &taken(&["r - soc"])),
            "R - soc 2"
        );
        assert_eq!(
            unique_stem("R - soc".into(), " ", &taken(&["r - soc"])),
            "R - soc 2"
        );
        assert_eq!(
            unique_stem(
                "R - soc".into(),
                "01234567",
                &taken(&["r - soc", "r - soc 01234567", "r - soc 2"])
            ),
            "R - soc 3"
        );
    }

    /// A single string where a list is expected is the one item it is: a
    /// rule's `tactics: "Execution"` is `- Execution`, not one item per
    /// character.
    #[test]
    fn a_single_string_is_one_item_of_a_list() {
        let rule = RULE.replace(
            "\"severity\": \"High\",",
            "\"severity\": \"High\", \"tactics\": \"Execution\", \"techniques\": \"T1059\",",
        );
        let (_, text) = render(&object(&rule), "soc").unwrap().unwrap();
        assert!(
            text.contains("\n      tactics:\n        - Execution\n"),
            "{text}"
        );
        assert!(
            text.contains("\n      techniques:\n        - T1059\n"),
            "{text}"
        );
        assert!(!text.contains("- E\n"), "{text}");
    }

    #[test]
    fn a_missing_or_mistyped_field_names_the_field() {
        let failed = |from: &str, to: &str| {
            render(&object(&RULE.replace(from, to)), "soc")
                .unwrap_err()
                .to_string()
        };
        assert_eq!(
            failed("\"triggerOperator\": \"GreaterThan\",", ""),
            "field `trigger_operator` is missing"
        );
        assert_eq!(
            failed("{\"enabled\": false}", "{}"),
            "field `incident_configuration.grouping_configuration.enabled` is missing"
        );
        assert_eq!(
            failed("\"queryPeriod\": \"PT1H\"", "\"queryPeriod\": 3"),
            "field `query_period` is not a string"
        );
        assert_eq!(
            failed(
                "\"incidentConfiguration\": {\"createIncident\": true,",
                "\"incidentConfiguration\": [], \"x\": {\"createIncident\": true,"
            ),
            "field `incident_configuration` is not a mapping"
        );
        assert_eq!(
            failed(
                "\"severity\": \"High\",",
                "\"severity\": \"High\", \"tactics\": 7,"
            ),
            "field `tactics` is not a list"
        );
    }
}
