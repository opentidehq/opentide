//! Microsoft Sentinel: a rule as the `Microsoft.SecurityInsights/alertRules`
//! PUT body for one tenant (`platforms/sentinel/deployer.py`
//! `compile_deployment`): `kind` and camelCase `properties`, unset fields left
//! out, in the oracle's key order.

use opentide_schema::objects::platform::SentinelConfig;
use opentide_schema::objects::platform::sentinel::{
    SentinelAlert, SentinelAlertGrouping, SentinelEntityMapping, Suppression,
};
use opentide_schema::vocab::sentinel::SentinelAttack;

use crate::Context;
use crate::deploy;
use crate::duration;
use crate::json::{Json, Object};
use crate::kql;
use crate::rule::{CompileError, Rule, codes};
use crate::strategy::StatusStrategy;
use crate::typed;

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

/// The code of the warning a technique newer than ATT&CK v18 earns.
pub const TECHNIQUE_NEWER_CODE: &str = "technique_newer_than_sentinel_attack";

/// A deploy's body and the `(code, message)` warnings it earned.
pub type Compiled = (Json, Vec<(&'static str, String)>);

/// The alert-rule body `rule` deploys to `tenant`.
pub fn compile(cx: &Context<'_>, rule: &Rule, tenant: &str) -> Result<Json, CompileError> {
    compile_with_warnings(cx, rule, tenant).map(|(body, _)| body)
}

/// The ids Sentinel takes for the `resolved` ATT&CK ids (the block's, else the
/// objective's), each change with a warning naming the rule, the id and what
/// is sent instead (see [`SentinelAttack::v18_replacement`]); an id v18 has
/// is kept.
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
        let (instead, why) = attack.v18_replacement(id);
        let mut message = if instead.is_empty() {
            format!("{label}: leaving out {id}, which is {why} and has no v{version} equivalent")
        } else {
            let names: Vec<&str> = instead.iter().map(|id| id.as_str()).collect();
            format!(
                "{label}: sending {} in place of {id}, which is {why}",
                names.join(" and ")
            )
        };
        if let Some(hint) = attack.sub_technique_map(id) {
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

/// The rule's Sentinel block, read by the model `opentide validate` checks it
/// with (`SentinelConfig`, #1951; [`typed::read_block`]): a block the model
/// refuses fails with the field path the rule wrote and the model's reason
/// (`configurations.sentinel.alert: Field required`).
///
/// A block whose only faults are values a field's or the block's own check
/// refuses (a duration it cannot read, a technique newer than ATT&CK v18, a
/// schedule outside Sentinel's bounds: `sentinel_frequency`,
/// `sentinel_lookback`) is compiled as before (`compile_invalid_rule` for an
/// unreadable duration, the v18 mapping and its warning for the technique,
/// the schedule sent as written); `validate` reports them.
fn block_of(rule: &Rule) -> Result<SentinelConfig, CompileError> {
    let Some(block) = rule.block("sentinel").filter(|block| block.is_filled()) else {
        return Err(CompileError::invalid_rule(format!(
            "Rule {} ({}): configurations.sentinel is missing",
            rule.uuid, rule.name
        )));
    };
    typed::read_block(block, "sentinel", DISPLAY)
}

/// The block's exclusions as written (`[{query, tenant, let}]`), which
/// [`kql::compile_query`] reads, once the model has read them. A `let`
/// value is taken from the rule, not the model: through serde a non-finite
/// float (`.inf`, `.nan`) would become `null`, and its `let` statement be
/// dropped.
fn exclusions<'a>(rule: &'a Rule, block: &SentinelConfig) -> Option<&'a Json> {
    block.exclusions.as_ref()?;
    rule.block("sentinel")?.get("exclusions")
}

/// [`compile`], with the warnings the body earned.
pub fn compile_with_warnings(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: &str,
) -> Result<Compiled, CompileError> {
    let mut warnings: Vec<(&'static str, String)> = Vec::new();
    let block = block_of(rule)?;
    let Some(grouping) = &block.grouping else {
        return Err(missing(
            "grouping",
            "Sentinel deploy requires grouping.event and grouping.alert",
        ));
    };
    let Some(alert_grouping) = &grouping.alert else {
        return Err(missing(
            "grouping.alert",
            "Sentinel deploy requires incident grouping (grouping.alert.enabled)",
        ));
    };
    let mut properties = Object::new();
    properties.insert("enabled".into(), Json::Bool(true));
    let exclusions = exclusions(rule, &block);
    properties.insert(
        "query".into(),
        Json::Str(kql::compile_query(&block.query, exclusions, tenant)),
    );
    let strategy = cx
        .statuses
        .strategy(&block.status)
        .map_err(|error| CompileError::failed(DISPLAY, &error.to_string()))?;
    if strategy == StatusStrategy::Disablement {
        properties.insert("enabled".into(), Json::Bool(false));
    }
    if let Some(template) = &block.template {
        properties.insert(
            "alertRuleTemplateName".into(),
            template.uuid.as_str().into(),
        );
        properties.insert("templateVersion".into(), template.version.as_str().into());
    }
    let alert = &block.alert;
    suppression(alert, &mut properties)?;
    let kind = schedule(&block, &mut properties)?;
    properties.insert(
        "alertDetailsOverride".into(),
        Json::Object(details_override(alert)),
    );
    if let Some(details) = alert.custom_details.as_ref().filter(|d| !d.is_empty()) {
        let mut custom = Object::new();
        for detail in details {
            custom.insert(detail.key.clone(), detail.column.as_str().into());
        }
        properties.insert("customDetails".into(), Json::Object(custom));
    }
    let mut event = Object::new();
    event.insert("aggregationKind".into(), grouping.event.as_str().into());
    properties.insert("eventGroupingSettings".into(), Json::Object(event));
    let mut incident = Object::new();
    incident.insert("createIncident".into(), Json::Bool(alert.create_incident));
    incident.insert(
        "groupingConfiguration".into(),
        Json::Object(grouping_configuration(alert_grouping)?),
    );
    properties.insert("incidentConfiguration".into(), Json::Object(incident));
    if let Some(entities) = block.entities.as_ref().filter(|e| !e.is_empty()) {
        properties.insert("entityMappings".into(), entity_mappings(entities));
    }
    let alert_severity = alert.severity.as_deref().filter(|text| !text.is_empty());
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
    techniques(cx, rule, alert, &mut properties, &mut warnings)?;
    let mut body = Object::new();
    body.insert("kind".into(), kind.into());
    body.insert("properties".into(), Json::Object(properties));
    Ok((Json::Object(body), warnings))
}

/// `suppressionEnabled` and `suppressionDuration` from `alert.suppression`.
fn suppression(alert: &SentinelAlert, properties: &mut Object) -> Result<(), CompileError> {
    match &alert.suppression {
        Suppression::Duration(suppression) => {
            properties.insert("suppressionEnabled".into(), Json::Bool(true));
            properties.insert("suppressionDuration".into(), Json::Str(iso(suppression)?));
            Ok(())
        }
        Suppression::Flag(false) => {
            properties.insert("suppressionEnabled".into(), Json::Bool(false));
            properties.insert("suppressionDuration".into(), Json::Str(iso("1h")?));
            Ok(())
        }
        Suppression::Flag(true) => Err(CompileError::new(
            codes::COMPILE_INVALID_VALUE,
            "configurations.sentinel.alert.suppression is true",
            Some("set it to false or a duration such as PT1H"),
        )
        .at(&["configurations", "sentinel", "alert", "suppression"])),
    }
}

/// `tactics`, `techniques` and `subTechniques`: the ATT&CK ids Sentinel
/// takes (the block's, else the objective's, each newer than v18 replaced
/// with a warning), and the block's tactics, else those of the ids sent.
fn techniques(
    cx: &Context<'_>,
    rule: &Rule,
    alert: &SentinelAlert,
    properties: &mut Object,
    warnings: &mut Vec<(&'static str, String)>,
) -> Result<(), CompileError> {
    let own = alert
        .techniques
        .iter()
        .flatten()
        .map(|technique| technique.0.clone())
        .collect();
    let resolved = deploy::platform_techniques(cx, DISPLAY, rule, own)?;
    let sendable = v18_techniques(
        &format!("Rule {} ({})", rule.uuid, rule.name),
        &resolved,
        warnings,
    );
    // The block's `alert.tactics` are sent when set; otherwise the tactics are
    // those of the techniques that are sent.
    if let Some(tactics) = alert.tactics.as_ref().filter(|t| !t.is_empty()) {
        properties.insert("tactics".into(), tactics.clone().into());
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
        if !subs.is_empty() {
            properties.insert("subTechniques".into(), subs.into());
        }
    }
    Ok(())
}

/// The rule's `kind`, NRT or Scheduled; a scheduled rule's frequency,
/// lookback and trigger written into `properties`.
fn schedule(block: &SentinelConfig, properties: &mut Object) -> Result<&'static str, CompileError> {
    let scheduling = &block.scheduling;
    if scheduling.nrt == Some(true) {
        return Ok("NRT");
    }
    let set = |value: &Option<String>| {
        value
            .as_deref()
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    };
    let Some(frequency) = set(&scheduling.frequency) else {
        return Err(missing(
            "scheduling.frequency",
            "required unless scheduling.nrt is true",
        ));
    };
    let Some(lookback) = set(&scheduling.lookback) else {
        return Err(missing(
            "scheduling.lookback",
            "required unless scheduling.nrt is true",
        ));
    };
    properties.insert("queryFrequency".into(), Json::Str(iso(&frequency)?));
    properties.insert("queryPeriod".into(), Json::Str(iso(&lookback)?));
    if let Some(trigger) = &block.trigger {
        properties.insert("triggerThreshold".into(), Json::Int(trigger.threshold));
        properties.insert("triggerOperator".into(), trigger.operator.as_str().into());
    }
    Ok("Scheduled")
}

/// `alertDetailsOverride`: the alert's title and description formats, and
/// its dynamic properties (Tactics and Severity by their own column keys).
fn details_override(alert: &SentinelAlert) -> Object {
    let mut overrides = Object::new();
    if let Some(title) = alert.title.as_deref().filter(|text| !text.is_empty()) {
        overrides.insert("alertDisplayNameFormat".into(), title.into());
    }
    if let Some(description) = alert.description.as_deref().filter(|text| !text.is_empty()) {
        overrides.insert("alertDescriptionFormat".into(), description.into());
    }
    if let Some(dynamic) = &alert.dynamic_properties {
        let mut properties_list = Vec::new();
        for property in dynamic {
            let column = Json::Str(property.column.clone());
            match property.property.as_str() {
                "Tactics" => {
                    overrides.insert("alertTacticsColumnName".into(), column);
                }
                "Severity" => {
                    overrides.insert("alertSeverityColumnName".into(), column);
                }
                name => {
                    let mut entry = Object::new();
                    entry.insert("alertProperty".into(), name.into());
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
    overrides
}

/// `incidentConfiguration.groupingConfiguration` from `grouping.alert`.
fn grouping_configuration(grouping: &SentinelAlertGrouping) -> Result<Object, CompileError> {
    let lookback = grouping
        .grouping_lookback
        .as_deref()
        .filter(|text| !text.is_empty());
    if grouping.enabled && lookback.is_none() {
        return Err(missing(
            "grouping.alert.grouping_lookback",
            "required when grouping.alert.enabled is true",
        ));
    }
    let mut configuration = Object::new();
    configuration.insert("enabled".into(), Json::Bool(grouping.enabled));
    configuration.insert(
        "lookbackDuration".into(),
        Json::Str(iso(lookback.unwrap_or("1h"))?),
    );
    configuration.insert(
        "reopenClosedIncident".into(),
        Json::Bool(grouping.reopen_closed_incidents == Some(true)),
    );
    configuration.insert(
        "matchingMethod".into(),
        grouping
            .matching
            .as_deref()
            .filter(|text| !text.is_empty())
            .unwrap_or("AllEntities")
            .into(),
    );
    for (key, field) in [
        ("groupByEntities", &grouping.group_by_entities),
        ("groupByAlertDetails", &grouping.group_by_alert_details),
        ("groupByCustomDetails", &grouping.group_by_custom_details),
    ] {
        if let Some(values) = field {
            configuration.insert(key.into(), values.clone().into());
        }
    }
    Ok(configuration)
}

/// `entityMappings`: each entity's type and its column mappings.
fn entity_mappings(entities: &[SentinelEntityMapping]) -> Json {
    Json::Array(
        entities
            .iter()
            .map(|entity| {
                let fields = entity
                    .mappings
                    .iter()
                    .map(|field| {
                        let mut mapping = Object::new();
                        mapping.insert("identifier".into(), field.identifier.as_str().into());
                        mapping.insert("columnName".into(), field.column.as_str().into());
                        Json::Object(mapping)
                    })
                    .collect();
                let mut mapping = Object::new();
                mapping.insert("entityType".into(), entity.entity.as_str().into());
                mapping.insert("fieldMappings".into(), Json::Array(fields));
                Json::Object(mapping)
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rule of the Sentinel `block` (YAML, indented under `sentinel:`).
    fn rule_of(block: &str) -> Rule {
        let text = format!(
            "name: R\nmetadata:\n  uuid: 00000000-0000-4000-8099-000000000001\n\
             response:\n  alert_severity: High\nconfigurations:\n  sentinel:\n{block}"
        );
        let document = opentide_schema::node::load(&text).unwrap();
        Rule::new(document.root().unwrap(), None)
    }

    const VALID: &str = "    status: STAGING\n    query: SecurityEvent\n    scheduling:\n      \
                         frequency: PT1H\n      lookback: PT1H\n    alert:\n      suppression: \
                         false\n";

    /// The block is read by `SentinelConfig` (#1951); an exclusion's `let`
    /// bindings keep their written order and their non-ASCII text.
    #[test]
    fn the_block_is_read_by_its_model_in_its_order() {
        let block = format!(
            "{VALID}    exclusions:\n      - query: '| where A != zeta'\n        reason: é\n        \
             let:\n          zeta: \"é😀\"\n          alpha: 1\n"
        );
        let rule = rule_of(&block);
        let config = block_of(&rule).unwrap();
        let exclusions = exclusions(&rule, &config);
        assert_eq!(
            exclusions.map(Json::to_compact).as_deref(),
            Some(r#"[{"query":"| where A != zeta","reason":"é","let":{"zeta":"é😀","alpha":1}}]"#)
        );
        assert_eq!(
            kql::compile_query(&config.query, exclusions, "t"),
            "let zeta = \"é😀\";\nlet alpha = 1;\nSecurityEvent\n| where A != zeta"
        );
    }

    /// The refusal of a block the model refuses: its code, field and reason.
    fn refusal(block: &str) -> CompileError {
        let error = block_of(&rule_of(block)).unwrap_err();
        assert_eq!(error.code, codes::COMPILE_FAILED, "{error}");
        assert_eq!(error.hint.as_deref(), Some(typed::REFUSED_HINT));
        // Nothing of an intermediate text or of serde's enum handling.
        assert!(!error.reason.contains("line 1"), "{error}");
        assert!(!error.reason.contains("untagged"), "{error}");
        error
    }

    /// A block the model refuses fails the compile, before any deploy check,
    /// at the field path the rule wrote and with the reason `validate`'s
    /// `schema` check gives (#1951); the old compile read past these.
    #[test]
    fn a_missing_alert_is_refused_at_its_path() {
        let error = refusal(&VALID.replace("    alert:\n      suppression: false\n", ""));
        assert_eq!(
            error.reason,
            "Sentinel cannot compile this rule: configurations.sentinel.alert: Field required"
        );
        assert_eq!(error.field, ["configurations", "sentinel", "alert"]);
    }

    #[test]
    fn an_unknown_key_is_refused_at_its_path() {
        let error = refusal(&format!(
            "{VALID}    grouping:\n      event: SingleAlert\n      alert:\n        enabled: false\n        \
             sevérity: 1\n"
        ));
        assert_eq!(
            error.reason,
            "Sentinel cannot compile this rule: configurations.sentinel.grouping.alert.sevérity: \
             Extra inputs are not permitted"
        );
        assert_eq!(
            error.field,
            [
                "configurations",
                "sentinel",
                "grouping",
                "alert",
                "sevérity"
            ]
        );
    }

    #[test]
    fn a_bad_suppression_is_refused_at_its_path() {
        let error = refusal(&VALID.replace("suppression: false", "suppression: 5"));
        assert!(
            error.reason.starts_with(
                "Sentinel cannot compile this rule: configurations.sentinel.alert.suppression: "
            ),
            "{error}"
        );
        assert_eq!(
            error.field,
            ["configurations", "sentinel", "alert", "suppression"]
        );
    }

    /// A value only a field's own check refuses is left to the compile,
    /// which refuses a duration it cannot read with its own code and words,
    /// as before.
    #[test]
    fn a_bad_duration_is_left_to_the_compile() {
        let config = block_of(&rule_of(
            &VALID.replace("frequency: PT1H", "frequency: bientôt"),
        ))
        .unwrap();
        let error = iso(&config.scheduling.frequency.unwrap()).unwrap_err();
        assert_eq!(error.code, codes::COMPILE_INVALID_RULE, "{error}");
        assert!(
            error.reason.starts_with("Duration \"bientôt\" is not"),
            "{error}"
        );
    }

    /// Every error the block earns is named, in the model's order.
    #[test]
    fn every_refusal_is_named() {
        let block = VALID.replace("    alert:\n      suppression: false\n", "") + "    bogus: 1\n";
        let error = refusal(&block);
        assert_eq!(
            error.reason,
            "Sentinel cannot compile this rule: configurations.sentinel.alert: Field required; \
             configurations.sentinel.bogus: Extra inputs are not permitted"
        );
        assert_eq!(error.field, ["configurations", "sentinel", "alert"]);
    }

    /// No block at all keeps its own error.
    #[test]
    fn no_block_keeps_its_own_error() {
        assert_eq!(
            block_of(&rule_of("    {}\n")).unwrap_err().code,
            codes::COMPILE_INVALID_RULE
        );
    }

    /// A non-finite `let` value keeps its `let` statement, as `real(...)`,
    /// as it did before the typed conversion, and so do a `-0.0` and a
    /// timestamp (a string in YAML 1.2). An integer past `i64` never gets
    /// here: the YAML loader refuses it.
    #[test]
    fn non_finite_let_values_are_kept() {
        let block = format!(
            "{VALID}    exclusions:\n      - query: '| where A != a'\n        reason: r\n        \
             let:\n          a: .inf\n          b: -.inf\n          c: .nan\n          d: -0.0\n          \
             f: 2024-01-01T00:00:00Z\n"
        );
        let rule = rule_of(&block);
        let config = block_of(&rule).unwrap();
        let old = kql::compile_query(&config.query, exclusions(&rule, &config), "t");
        assert!(
            old.starts_with(
                "let a = real(+inf);\nlet b = real(-inf);\nlet c = real(nan);\nlet d = -0.0;\n"
            ),
            "{old}"
        );
        assert!(old.contains("let f = \"2024-01-01T00:00:00Z\";"), "{old}");
        assert_eq!(old.matches("let ").count(), 5, "{old}");
    }

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
