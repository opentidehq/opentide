//! Microsoft Sentinel: a rule as the `Microsoft.SecurityInsights/alertRules`
//! PUT body for one tenant (`platforms/sentinel/deployer.py`
//! `compile_deployment`): `kind` and camelCase `properties`, unset fields left
//! out, in the oracle's key order.

use opentide_schema::vocab::sentinel::SentinelAttack;

use crate::Context;
use crate::duration;
use crate::json::{Json, Object};
use crate::kql;
use crate::rule::{CompileError, Rule};
use crate::strategy::{StatusStrategy, python_repr};

/// The platform's display name, in messages.
pub const DISPLAY: &str = "Sentinel";

/// The ARM `AttackTactic` values.
const TACTICS: [&str; 17] = [
    "Reconnaissance",
    "ResourceDevelopment",
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Collection",
    "Exfiltration",
    "CommandAndControl",
    "Impact",
    "PreAttack",
    "ImpairProcessControl",
    "InhibitResponseFunction",
];

/// Python's `str.title`: each run of letters capitalised.
fn title(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_word = false;
    for c in text.chars() {
        if c.is_alphabetic() {
            if in_word {
                out.extend(c.to_lowercase());
            } else {
                out.extend(c.to_uppercase());
            }
            in_word = true;
        } else {
            out.push(c);
            in_word = false;
        }
    }
    out
}

/// The Sentinel tactic of an `att&ck` stage (`sentinel_tactic`): ATT&CK v19's
/// Stealth and Defense Impairment, and ICS's Evasion, are `DefenseEvasion`.
pub fn tactic(stage: &str) -> Option<&'static str> {
    let name = title(stage).replace(' ', "");
    let name = name.trim();
    let name = match name {
        "Stealth" | "DefenseImpairment" | "Evasion" => "DefenseEvasion",
        other => other,
    };
    TACTICS.iter().find(|tactic| **tactic == name).copied()
}

/// ATT&CK ids split into the ARM `techniques` (each id's parent) and
/// `subTechniques` lists, both de-duplicated in order (`split_techniques`).
pub fn split_techniques(ids: &[String]) -> (Vec<String>, Vec<String>) {
    let mut techniques: Vec<String> = Vec::new();
    let mut subs: Vec<String> = Vec::new();
    for id in ids {
        let parent = id.split('.').next().unwrap_or(id).to_owned();
        if !techniques.contains(&parent) {
            techniques.push(parent);
        }
        if id.contains('.') && !subs.contains(id) {
            subs.push(id.clone());
        }
    }
    (techniques, subs)
}

fn missing(field: &str, requirement: &str) -> CompileError {
    let mut path = vec!["configurations", "sentinel"];
    path.extend(field.split('.'));
    CompileError::new(
        "compile_missing_field",
        format!("configurations.sentinel.{field} is missing"),
        Some(requirement),
    )
    .at(&path)
}

/// A duration as the API takes it; a duration it cannot read refuses the rule
/// as the oracle's data model does.
fn iso(value: &str) -> Result<String, CompileError> {
    duration::sentinel(value).map_err(CompileError::invalid_rule)
}

/// A string the block sets, Python-truthy.
fn text<'j>(object: Option<&'j Json>, key: &str) -> Option<&'j str> {
    object
        .and_then(|object| object.get(key))
        .and_then(Json::as_str)
        .filter(|text| !text.is_empty())
}

/// A duration field, given as the model reads it: a string, or the text of a
/// number.
fn duration_text(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        other => other.to_compact(),
    }
}

/// The strings of a list.
fn strings(value: Option<&Json>) -> Vec<String> {
    match value {
        Some(Json::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The alert-rule body `rule` deploys to `tenant`.
pub fn compile(cx: &Context<'_>, rule: &Rule, tenant: &str) -> Result<Json, CompileError> {
    let Some(block) = rule.block("sentinel").filter(|block| block.truthy()) else {
        return Err(CompileError::invalid_rule(format!(
            "Rule {} ({}): configurations.sentinel is missing",
            rule.uuid, rule.name
        )));
    };
    let grouping = block.get("grouping").filter(|grouping| grouping.truthy());
    let Some(grouping) = grouping else {
        return Err(missing(
            "grouping",
            "Sentinel deploy requires grouping.event and grouping.alert",
        ));
    };
    let Some(alert_grouping) = grouping.get("alert").filter(|alert| alert.truthy()) else {
        return Err(missing(
            "grouping.alert",
            "Sentinel deploy requires incident grouping (grouping.alert.enabled)",
        ));
    };
    let mut kind = "Scheduled";
    let mut properties = Object::new();
    properties.insert("enabled".into(), Json::Bool(true));
    let query = block
        .get("query")
        .and_then(Json::as_str)
        .unwrap_or_default();
    properties.insert(
        "query".into(),
        Json::Str(kql::compile_query(query, block.get("exclusions"), tenant)),
    );
    let status = block
        .get("status")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let strategy = cx
        .statuses
        .strategy(status)
        .map_err(|error| CompileError::failed(DISPLAY, &error.exception_text()))?;
    if strategy == StatusStrategy::Disablement {
        properties.insert("enabled".into(), Json::Bool(false));
    }
    if let Some(template) = block.get("template").filter(|template| template.truthy()) {
        properties.insert(
            "alertRuleTemplateName".into(),
            template.get("uuid").cloned().unwrap_or(Json::Null),
        );
        properties.insert(
            "templateVersion".into(),
            template.get("version").cloned().unwrap_or(Json::Null),
        );
    }
    let alert = block.get("alert");
    match alert.and_then(|alert| alert.get("suppression")) {
        Some(Json::Str(suppression)) => {
            properties.insert("suppressionEnabled".into(), Json::Bool(true));
            properties.insert("suppressionDuration".into(), Json::Str(iso(suppression)?));
        }
        None | Some(Json::Bool(false) | Json::Null) => {
            properties.insert("suppressionEnabled".into(), Json::Bool(false));
            properties.insert("suppressionDuration".into(), Json::Str(iso("1h")?));
        }
        Some(_) => {
            return Err(CompileError::new(
                "compile_invalid_value",
                "configurations.sentinel.alert.suppression is true",
                Some("set it to false or a duration such as PT1H"),
            )
            .at(&["configurations", "sentinel", "alert", "suppression"]));
        }
    }
    let scheduling = block.get("scheduling");
    let nrt = matches!(
        scheduling.and_then(|scheduling| scheduling.get("nrt")),
        Some(Json::Bool(true))
    );
    if nrt {
        kind = "NRT";
    } else {
        let frequency = scheduling
            .and_then(|scheduling| scheduling.get("frequency"))
            .filter(|value| value.truthy());
        let Some(frequency) = frequency else {
            return Err(missing(
                "scheduling.frequency",
                "required unless scheduling.nrt is true",
            ));
        };
        let lookback = scheduling
            .and_then(|scheduling| scheduling.get("lookback"))
            .filter(|value| value.truthy());
        let Some(lookback) = lookback else {
            return Err(missing(
                "scheduling.lookback",
                "required unless scheduling.nrt is true",
            ));
        };
        properties.insert(
            "queryFrequency".into(),
            Json::Str(iso(&duration_text(frequency))?),
        );
        properties.insert(
            "queryPeriod".into(),
            Json::Str(iso(&duration_text(lookback))?),
        );
        if let Some(trigger) = block.get("trigger").filter(|trigger| trigger.truthy()) {
            properties.insert(
                "triggerThreshold".into(),
                trigger.get("threshold").cloned().unwrap_or(Json::Null),
            );
            properties.insert(
                "triggerOperator".into(),
                trigger.get("operator").cloned().unwrap_or(Json::Null),
            );
        }
    }
    let mut overrides = Object::new();
    if let Some(title) = text(alert, "title") {
        overrides.insert("alertDisplayNameFormat".into(), title.into());
    }
    if let Some(description) = text(alert, "description") {
        overrides.insert("alertDescriptionFormat".into(), description.into());
    }
    if let Some(Json::Array(dynamic)) = alert.and_then(|alert| alert.get("dynamic_properties")) {
        let mut properties_list = Vec::new();
        for property in dynamic {
            let name = property.get("property").cloned().unwrap_or(Json::Null);
            let column = property.get("column").cloned().unwrap_or(Json::Null);
            match name.as_str() {
                Some("Tactics") => {
                    overrides.insert("alertTacticsColumnName".into(), column);
                }
                Some("Severity") => {
                    overrides.insert("alertSeverityColumnName".into(), column);
                }
                _ => {
                    let mut entry = Object::new();
                    entry.insert("alertProperty".into(), name);
                    entry.insert("value".into(), column);
                    properties_list.push(Json::Object(entry));
                }
            }
        }
        if !properties_list.is_empty() {
            overrides.insert(
                "alertDynamicProperties".into(),
                Json::Array(properties_list),
            );
        }
    }
    properties.insert("alertDetailsOverride".into(), Json::Object(overrides));
    let alert_techniques = strings(alert.and_then(|alert| alert.get("techniques")));
    if !alert_techniques.is_empty() {
        let (techniques, subs) = split_techniques(&alert_techniques);
        properties.insert("techniques".into(), techniques.into());
        if !subs.is_empty() {
            properties.insert("subTechniques".into(), subs.into());
        }
    }
    if let Some(tactics) = alert
        .and_then(|alert| alert.get("tactics"))
        .filter(|tactics| tactics.truthy())
    {
        properties.insert("tactics".into(), tactics.clone());
    }
    if let Some(Json::Array(details)) = alert.and_then(|alert| alert.get("custom_details"))
        && !details.is_empty()
    {
        let mut custom = Object::new();
        for detail in details {
            let key = match detail.get("key") {
                Some(Json::Str(key)) => key.clone(),
                Some(other) => other.to_compact(),
                None => "null".to_owned(),
            };
            custom.insert(key, detail.get("column").cloned().unwrap_or(Json::Null));
        }
        properties.insert("customDetails".into(), Json::Object(custom));
    }
    let mut event = Object::new();
    event.insert(
        "aggregationKind".into(),
        grouping.get("event").cloned().unwrap_or(Json::Null),
    );
    properties.insert("eventGroupingSettings".into(), Json::Object(event));
    let create_incident = alert
        .and_then(|alert| alert.get("create_incident"))
        .cloned()
        .unwrap_or(Json::Bool(true));
    let enabled = alert_grouping.get("enabled").cloned().unwrap_or(Json::Null);
    let lookback = alert_grouping
        .get("grouping_lookback")
        .filter(|value| value.truthy());
    if enabled.truthy() && lookback.is_none() {
        return Err(missing(
            "grouping.alert.grouping_lookback",
            "required when grouping.alert.enabled is true",
        ));
    }
    let mut configuration = Object::new();
    configuration.insert("enabled".into(), enabled);
    configuration.insert(
        "lookbackDuration".into(),
        Json::Str(iso(
            &lookback.map_or_else(|| "1h".to_owned(), duration_text)
        )?),
    );
    configuration.insert(
        "reopenClosedIncident".into(),
        alert_grouping
            .get("reopen_closed_incidents")
            .filter(|value| value.truthy())
            .cloned()
            .unwrap_or(Json::Bool(false)),
    );
    configuration.insert(
        "matchingMethod".into(),
        alert_grouping
            .get("matching")
            .filter(|value| value.truthy())
            .cloned()
            .unwrap_or_else(|| "AllEntities".into()),
    );
    for (key, field) in [
        ("groupByEntities", "group_by_entities"),
        ("groupByAlertDetails", "group_by_alert_details"),
        ("groupByCustomDetails", "group_by_custom_details"),
    ] {
        if let Some(value) = alert_grouping.get(field).filter(|value| !value.is_null()) {
            configuration.insert(key.into(), value.clone());
        }
    }
    let mut incident = Object::new();
    incident.insert("createIncident".into(), create_incident);
    incident.insert("groupingConfiguration".into(), Json::Object(configuration));
    properties.insert("incidentConfiguration".into(), Json::Object(incident));
    if let Some(Json::Array(entities)) = block.get("entities")
        && !entities.is_empty()
    {
        let mappings = entities
            .iter()
            .map(|entity| {
                let fields = match entity.get("mappings") {
                    Some(Json::Array(fields)) => fields
                        .iter()
                        .map(|field| {
                            let mut mapping = Object::new();
                            mapping.insert(
                                "identifier".into(),
                                field.get("identifier").cloned().unwrap_or(Json::Null),
                            );
                            mapping.insert(
                                "columnName".into(),
                                field.get("column").cloned().unwrap_or(Json::Null),
                            );
                            Json::Object(mapping)
                        })
                        .collect(),
                    _ => Vec::new(),
                };
                let mut mapping = Object::new();
                mapping.insert(
                    "entityType".into(),
                    entity.get("entity").cloned().unwrap_or(Json::Null),
                );
                mapping.insert("fieldMappings".into(), Json::Array(fields));
                Json::Object(mapping)
            })
            .collect();
        properties.insert("entityMappings".into(), Json::Array(mappings));
    }
    let alert_severity = text(alert, "severity");
    if alert_severity.is_none() && rule.response().is_none() {
        return Err(CompileError::new(
            "compile_empty_block",
            "`response` is empty, so Sentinel cannot read `alert_severity`",
            Some("set response.alert_severity, or configurations.sentinel.alert.severity"),
        )
        .at(&["response"]));
    }
    let mut severity = alert_severity.unwrap_or_else(|| rule.alert_severity());
    if severity == "Critical" {
        severity = "High";
    }
    properties.insert("severity".into(), severity.into());
    properties.insert("displayName".into(), rule.name.clone().into());
    properties.insert("description".into(), rule.description().into());
    let resolved = crate::attack::techniques(cx.index, &rule.uuid)
        .map_err(|missing| CompileError::failed(DISPLAY, &python_repr(&missing.0)))?;
    if !resolved.is_empty() {
        let mut tactics: Vec<String> = Vec::new();
        for technique in &resolved {
            for stage in cx.attack.stages(technique) {
                if let Some(tactic) = tactic(&stage)
                    && !tactics.iter().any(|known| known == tactic)
                {
                    tactics.push(tactic.to_owned());
                }
            }
        }
        properties.insert("tactics".into(), tactics.into());
        let (techniques, subs) = split_techniques(&resolved);
        properties.insert("techniques".into(), techniques.into());
        let known = &SentinelAttack::bundled().techniques;
        let subs: Vec<String> = subs
            .into_iter()
            .filter(|id| known.contains_key(id))
            .collect();
        properties.insert(
            "subTechniques".into(),
            if subs.is_empty() {
                Json::Null
            } else {
                subs.into()
            },
        );
    }
    properties.retain(|_, value| !value.is_null());
    let mut body = Object::new();
    body.insert("kind".into(), kind.into());
    body.insert("properties".into(), Json::Object(properties));
    Ok(Json::Object(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stages_become_sentinel_tactics() {
        assert_eq!(tactic("Command and Control"), Some("CommandAndControl"));
        assert_eq!(tactic("stealth"), Some("DefenseEvasion"));
        assert_eq!(tactic("Defense Impairment"), Some("DefenseEvasion"));
        assert_eq!(tactic("Privilege Escalation"), Some("PrivilegeEscalation"));
        assert_eq!(tactic("Network Effects"), None);
    }

    #[test]
    fn sub_techniques_are_split_from_their_parents() {
        let ids: Vec<String> = ["T1556.009", "T1556", "T1059.001", "T1059.001"]
            .iter()
            .map(|id| (*id).to_owned())
            .collect();
        let (techniques, subs) = split_techniques(&ids);
        assert_eq!(techniques, ["T1556", "T1059"]);
        assert_eq!(subs, ["T1556.009", "T1059.001"]);
    }

    #[test]
    fn title_is_pythons() {
        assert_eq!(title("command and control"), "Command And Control");
        assert_eq!(title("PRE-attack"), "Pre-Attack");
    }
}
