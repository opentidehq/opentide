//! Microsoft Sentinel: a rule as the `Microsoft.SecurityInsights/alertRules`
//! PUT body for one tenant (`platforms/sentinel/deployer.py`
//! `compile_deployment`): `kind` and camelCase `properties`, unset fields left
//! out, in the oracle's key order.

use opentide_schema::vocab::sentinel::SentinelAttack;

use crate::Context;
use crate::deploy::{self, strings};
use crate::duration;
use crate::json::{Json, Object};
use crate::kql;
use crate::rule::{CompileError, Rule, codes};
use crate::strategy::StatusStrategy;

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

/// Title case: the first letter of each run of letters upper case, the rest
/// lower case.
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
        codes::COMPILE_MISSING_FIELD,
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

/// A string the block sets, not empty.
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

/// The code of the warning a technique newer than ATT&CK v18 earns.
pub const TECHNIQUE_NEWER_CODE: &str = "technique_newer_than_sentinel_attack";

/// A deploy's body and the `(code, message)` warnings it earned.
pub type Compiled = (Json, Vec<(&'static str, String)>);

/// The alert-rule body `rule` deploys to `tenant`.
pub fn compile(cx: &Context<'_>, rule: &Rule, tenant: &str) -> Result<Json, CompileError> {
    compile_with_warnings(cx, rule, tenant).map(|(body, _)| body)
}

/// What v18 holds in place of `id`, an id it does not know, and why: the v18
/// ids that replace it (none when it has no equivalent), and the reason.
///
/// - an id newer than v18 becomes the v18 id(s) it replaced; with none, its
///   v18 parent when it is a sub-technique (`T1027.018` sends `T1027`), or the
///   v18 parents its newer parent replaced (`T1685.007` sends `T1562`);
/// - a retired id becomes the id(s) that replaced it;
/// - an id the list does not know at all has none.
fn v18_replacement<'a>(attack: &'a SentinelAttack, id: &str) -> (Vec<&'a String>, String) {
    let version = opentide_schema::vocab::sentinel::VERSION;
    let known = |id: &&String| attack.techniques.contains_key(*id);
    if let Some(newer) = attack.later.techniques.get(id) {
        let replaced: Vec<&String> = newer.replaces.iter().filter(known).collect();
        let instead = if replaced.is_empty() {
            // A sub-technique with no replacement stands for its parent: the
            // parent when v18 has it, else the parent's own v18 parents (the
            // dot-free ids it replaced).
            id.split_once('.')
                .map(|(parent, _)| {
                    attack.techniques.get_key_value(parent).map_or_else(
                        || {
                            attack
                                .later
                                .techniques
                                .get(parent)
                                .map(|newer| {
                                    newer
                                        .replaces
                                        .iter()
                                        .filter(|old| !old.contains('.'))
                                        .filter(known)
                                        .collect()
                                })
                                .unwrap_or_default()
                        },
                        |(parent, _)| vec![parent],
                    )
                })
                .unwrap_or_default()
        } else {
            replaced
        };
        (instead, format!("newer than ATT&CK v{version}"))
    } else if let Some(retired) = attack.retired.get(id) {
        (
            retired.replaced_by.iter().filter(known).collect(),
            format!("retired before ATT&CK v{version}"),
        )
    } else {
        (
            Vec::new(),
            format!("not an ATT&CK v{version} id Sentinel knows"),
        )
    }
}

/// For a parent technique newer than ATT&CK v18, where its sub-technique ids
/// go, as deploy sends them: `Its sub-techniques map to ATT&CK v18 as
/// T1685.002 → T1562.008, ...` (`none` for one with no v18 equivalent). `None`
/// for a sub-technique or an id the list does not hold as newer.
fn sub_technique_hint(attack: &SentinelAttack, id: &str) -> Option<String> {
    if id.contains('.') || !attack.later.techniques.contains_key(id) {
        return None;
    }
    let prefix = format!("{id}.");
    let version = opentide_schema::vocab::sentinel::VERSION;
    let mappings: Vec<String> = attack
        .later
        .techniques
        .keys()
        .filter(|sub| sub.starts_with(&prefix))
        .map(|sub| {
            let (instead, _) = v18_replacement(attack, sub);
            if instead.is_empty() {
                format!("{sub} → none")
            } else {
                let names: Vec<&str> = instead.iter().map(|id| id.as_str()).collect();
                format!("{sub} → {}", names.join(" and "))
            }
        })
        .collect();
    if mappings.is_empty() {
        return None;
    }
    Some(format!(
        "Its sub-techniques map to ATT&CK v{version} as {}",
        mappings.join(", ")
    ))
}

/// The ids Sentinel takes for the `resolved` ATT&CK ids (the block's, else the
/// objective's), each change with a warning naming the rule, the id and what
/// is sent instead (see [`v18_replacement`]); an id v18 has is kept.
fn v18_techniques(
    label: &str,
    resolved: &[String],
    warnings: &mut Vec<(&'static str, String)>,
) -> Vec<String> {
    let attack = SentinelAttack::bundled();
    let version = opentide_schema::vocab::sentinel::VERSION;
    let mut out: Vec<String> = Vec::new();
    for id in resolved {
        if attack.techniques.contains_key(id) {
            if !out.contains(id) {
                out.push(id.clone());
            }
            continue;
        }
        let (instead, why) = v18_replacement(attack, id);
        let mut message = if instead.is_empty() {
            format!("{label}: leaving out {id}, which is {why} and has no v{version} equivalent")
        } else {
            let names: Vec<&str> = instead.iter().map(|id| id.as_str()).collect();
            format!(
                "{label}: sending {} in place of {id}, which is {why}",
                names.join(" and ")
            )
        };
        if let Some(hint) = sub_technique_hint(attack, id) {
            message.push_str(". ");
            message.push_str(&hint);
        }
        warnings.push((TECHNIQUE_NEWER_CODE, message));
        for id in instead {
            if !out.contains(id) {
                out.push(id.clone());
            }
        }
    }
    out
}

/// [`compile`], with the warnings the body earned.
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
pub fn compile_with_warnings(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: &str,
) -> Result<Compiled, CompileError> {
    let mut warnings: Vec<(&'static str, String)> = Vec::new();
    let Some(block) = rule.block("sentinel").filter(|block| block.is_filled()) else {
        return Err(CompileError::invalid_rule(format!(
            "Rule {} ({}): configurations.sentinel is missing",
            rule.uuid, rule.name
        )));
    };
    let grouping = block
        .get("grouping")
        .filter(|grouping| grouping.is_filled());
    let Some(grouping) = grouping else {
        return Err(missing(
            "grouping",
            "Sentinel deploy requires grouping.event and grouping.alert",
        ));
    };
    let Some(alert_grouping) = grouping.get("alert").filter(|alert| alert.is_filled()) else {
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
        .map_err(|error| CompileError::failed(DISPLAY, &error.to_string()))?;
    if strategy == StatusStrategy::Disablement {
        properties.insert("enabled".into(), Json::Bool(false));
    }
    if let Some(template) = block
        .get("template")
        .filter(|template| template.is_filled())
    {
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
                codes::COMPILE_INVALID_VALUE,
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
            .filter(|value| value.is_filled());
        let Some(frequency) = frequency else {
            return Err(missing(
                "scheduling.frequency",
                "required unless scheduling.nrt is true",
            ));
        };
        let lookback = scheduling
            .and_then(|scheduling| scheduling.get("lookback"))
            .filter(|value| value.is_filled());
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
        if let Some(trigger) = block.get("trigger").filter(|trigger| trigger.is_filled()) {
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
        .filter(|value| value.is_filled());
    if enabled.is_true() && lookback.is_none() {
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
            .filter(|value| value.is_true())
            .cloned()
            .unwrap_or(Json::Bool(false)),
    );
    configuration.insert(
        "matchingMethod".into(),
        alert_grouping
            .get("matching")
            .filter(|value| value.is_filled())
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
            codes::COMPILE_EMPTY_BLOCK,
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
    let resolved = deploy::platform_techniques(
        cx,
        DISPLAY,
        rule,
        strings(alert.and_then(|alert| alert.get("techniques"))),
    )?;
    let sendable = v18_techniques(
        &format!("Rule {} ({})", rule.uuid, rule.name),
        &resolved,
        &mut warnings,
    );
    // The block's `alert.tactics` are sent when set; otherwise the tactics are
    // those of the techniques that are sent.
    if let Some(tactics) = alert
        .and_then(|alert| alert.get("tactics"))
        .filter(|tactics| tactics.is_filled())
    {
        properties.insert("tactics".into(), tactics.clone());
    } else if !sendable.is_empty() {
        let mut tactics: Vec<String> = Vec::new();
        for technique in &sendable {
            for stage in cx.attack.stages(technique) {
                if let Some(tactic) = tactic(&stage)
                    && !tactics.iter().any(|known| known == tactic)
                {
                    tactics.push(tactic.to_owned());
                }
            }
        }
        properties.insert("tactics".into(), tactics.into());
    }
    if !sendable.is_empty() {
        let (techniques, subs) = split_techniques(&sendable);
        properties.insert("techniques".into(), techniques.into());
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
    Ok((Json::Object(body), warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stages_become_sentinel_tactics() {
        assert_eq!(tactic("Command and Control"), Some("CommandAndControl"));
        assert_eq!(tactic("stealth"), Some("DefenseEvasion"));
        assert_eq!(tactic("Defense Impairment"), Some("DefenseEvasion"));
        assert_eq!(tactic("Evasion"), Some("DefenseEvasion"));
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
    fn techniques_newer_than_v18_map_to_their_v18_ids() {
        let ids: Vec<String> = ["T1562.008", "T1562.001", "T1685.002", "T1070.002"]
            .iter()
            .map(|id| (*id).to_owned())
            .collect();
        let mut warnings = Vec::new();
        let sendable = v18_techniques("Rule r (n)", &ids, &mut warnings);
        assert_eq!(sendable, ["T1562.008", "T1562.001", "T1070.002"]);
        let (parents, subs) = split_techniques(&sendable);
        assert_eq!(parents, ["T1562", "T1070"]);
        assert_eq!(subs, ["T1562.008", "T1562.001", "T1070.002"]);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].0, TECHNIQUE_NEWER_CODE);
        assert!(warnings[0].1.contains("Rule r (n)"), "{}", warnings[0].1);
        assert!(warnings[0].1.contains("T1562.008 in place of T1685.002"));
    }

    #[test]
    fn a_newer_sub_technique_without_a_replacement_sends_its_v18_parent() {
        let mut warnings = Vec::new();
        let sendable = v18_techniques("Rule r (n)", &["T1027.018".into()], &mut warnings);
        assert_eq!(sendable, ["T1027"]);
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0]
                .1
                .contains("sending T1027 in place of T1027.018"),
            "{}",
            warnings[0].1
        );
    }

    #[test]
    fn a_newer_sub_technique_of_a_newer_parent_sends_the_parents_v18_parents() {
        let mut warnings = Vec::new();
        let sendable = v18_techniques(
            "Rule r (n)",
            &["T1685.007".into(), "T1686.003".into()],
            &mut warnings,
        );
        // T1685 replaced T1562 (and two of its sub-techniques); T1686 replaced
        // only a sub-technique, so nothing is dot-free.
        assert_eq!(sendable, ["T1562"]);
        assert!(
            warnings[0]
                .1
                .contains("sending T1562 in place of T1685.007"),
            "{}",
            warnings[0].1
        );
        assert!(
            warnings[1].1.contains("leaving out T1686.003"),
            "{}",
            warnings[1].1
        );
    }

    #[test]
    fn a_newer_parent_without_a_v18_equivalent_is_left_out_with_a_warning() {
        let mut warnings = Vec::new();
        let sendable = v18_techniques(
            "Rule r (n)",
            &["T1691".into(), "T1059".into()],
            &mut warnings,
        );
        assert_eq!(sendable, ["T1059"]);
        assert!(
            warnings[0].1.contains("leaving out T1691"),
            "{}",
            warnings[0].1
        );
    }

    #[test]
    fn unknown_and_retired_ids_are_named_as_such() {
        let mut warnings = Vec::new();
        let sendable = v18_techniques(
            "Rule r (n)",
            &["T9999".into(), "T1002".into(), "T1476".into()],
            &mut warnings,
        );
        assert_eq!(sendable, ["T1560"]);
        assert!(
            warnings[0]
                .1
                .contains("not an ATT&CK v18 id Sentinel knows"),
            "{}",
            warnings[0].1
        );
        assert!(warnings[1].1.contains("sending T1560 in place of T1002"));
        assert!(
            warnings[2].1.contains("leaving out T1476"),
            "{}",
            warnings[2].1
        );
    }

    #[test]
    fn title_is_pythons() {
        assert_eq!(title("command and control"), "Command And Control");
        assert_eq!(title("PRE-attack"), "Pre-Attack");
    }
}
