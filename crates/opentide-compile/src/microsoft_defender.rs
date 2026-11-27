//! Microsoft Defender: the custom detection rule a deploy sends to one
//! tenant through the Microsoft Graph beta custom detection API
//! (microsoft-defender-1.0, Request body). Create and update send the same
//! body; create adds `id`, the rule's Defender rule id ([`rule_id`]:
//! `opentide-` and its lowercase canonical `metadata.uuid`, #1886).
//! A key the block leaves unset is omitted, never sent as `null`, and no
//! deprecated Graph property is sent.

use std::collections::{BTreeMap, BTreeSet};

use opentide_schema::objects::platform::microsoft_defender::{
    ACTIONS, DEVICE_GROUPS, Duration, ENTITY_KINDS, GROUPINGS, Kind, PLATFORM,
};

use crate::Context;
use crate::attack;
use crate::deploy::{self, Write, strings};
use crate::json::{Json, Object};
use crate::kql;
use crate::rule::{CompileError, Rule, canonical_uuid};
use crate::strategy::StatusStrategy;

/// The platform's display name, in messages.
pub const DISPLAY: &str = "Microsoft Defender";

/// The detection rules collection of the Graph beta API (`{base}`).
pub const ENDPOINT: &str = "https://graph.microsoft.com/beta/security/rules/detectionRules";

/// The code of the warning a technique deploy leaves out earns: one outside
/// Enterprise ATT&CK, or one the `att&ck` vocabulary does not know.
pub const TECHNIQUE_LEFT_OUT_CODE: &str = "technique_not_enterprise_left_out";

/// The Graph `tactic` of each `att&ck` stage, in the order Graph's
/// `tactics` lists them (microsoft-defender-1.0, ATT&CK). Stealth and Defense
/// Impairment, ATT&CK v19's split of Defense Evasion, are both
/// `DefenseEvasion`.
pub const TACTICS: [(&str, &str); 15] = [
    ("Reconnaissance", "Reconnaissance"),
    ("Resource Development", "ResourceDevelopment"),
    ("Initial Access", "InitialAccess"),
    ("Execution", "Execution"),
    ("Persistence", "Persistence"),
    ("Privilege Escalation", "PrivilegeEscalation"),
    ("Stealth", "DefenseEvasion"),
    ("Defense Impairment", "DefenseEvasion"),
    ("Credential Access", "CredentialAccess"),
    ("Discovery", "Discovery"),
    ("Lateral Movement", "LateralMovement"),
    ("Collection", "Collection"),
    ("Command and Control", "CommandAndControl"),
    ("Exfiltration", "Exfiltration"),
    ("Impact", "Impact"),
];

/// The position in Graph's order of the tactic of a vocabulary stage (its
/// name in any case; the legacy `Defense Evasion` is Stealth), or `None`
/// for a stage outside the table.
fn tactic_rank(stage: &str) -> Option<usize> {
    let (name, _) = attack::tactic(stage)?;
    let graph = TACTICS
        .iter()
        .find(|(stage, _)| *stage == name)
        .map(|(_, graph)| *graph)?;
    // Both of DefenseEvasion's stages rank as the first.
    TACTICS.iter().position(|(_, tactic)| *tactic == graph)
}

/// Graph's severity of an opentide severity: lower-cased, `Critical` as
/// `high`.
fn severity(name: &str) -> Result<&'static str, CompileError> {
    Ok(match name {
        "Informational" => "informational",
        "Low" => "low",
        "Medium" => "medium",
        "High" | "Critical" => "high",
        other => return Err(CompileError::failed(DISPLAY, &format!("{other:?}"))),
    })
}

/// A string the block sets, not empty.
fn text<'j>(value: Option<&'j Json>, key: &str) -> Option<&'j str> {
    value
        .and_then(|value| value.get(key))
        .and_then(Json::as_str)
        .filter(|text| !text.is_empty())
}

/// A block's warnings: `(code, message)`.
pub type Warnings = Vec<(&'static str, String)>;

/// The alert's `tactics`, derived from `ids` (microsoft-defender-1.0,
/// ATT&CK), and the warnings of the ids left out; `None` when no technique
/// is left.
pub fn tactics(cx: &Context<'_>, rule: &Rule, ids: &[String]) -> (Option<Json>, Warnings) {
    let mut warnings = Vec::new();
    // tactic rank -> parent -> sub-techniques
    let mut tree: BTreeMap<usize, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    for id in ids {
        let Some(name) = cx.attack.name(id) else {
            warnings.push((
                TECHNIQUE_LEFT_OUT_CODE,
                format!(
                    "Rule {} ({}): leaving out {id}, which the att&ck vocabulary does not know, so \
                     {DISPLAY} cannot file it under a tactic",
                    rule.uuid, rule.name
                ),
            ));
            continue;
        };
        if attack::non_enterprise(name) {
            warnings.push((
                TECHNIQUE_LEFT_OUT_CODE,
                format!(
                    "Rule {} ({}): leaving out {id}, which is not an Enterprise ATT&CK \
                     technique, so {DISPLAY} does not take it",
                    rule.uuid, rule.name
                ),
            ));
            continue;
        }
        let (parent, sub) = match id.split_once('.') {
            Some((parent, _)) => (parent.to_owned(), Some(id.clone())),
            None => (id.clone(), None),
        };
        for stage in cx.attack.stages(id) {
            let Some(rank) = tactic_rank(&stage) else {
                continue;
            };
            let subs = tree
                .entry(rank)
                .or_default()
                .entry(parent.clone())
                .or_default();
            if let Some(sub) = &sub {
                subs.insert(sub.clone());
            }
        }
    }
    if tree.is_empty() {
        return (None, warnings);
    }
    let tactics = tree
        .into_iter()
        .map(|(rank, techniques)| {
            let mut tactic = Object::new();
            tactic.insert("tactic".into(), TACTICS[rank].1.into());
            let techniques = techniques
                .into_iter()
                .map(|(parent, subs)| {
                    let mut technique = Object::new();
                    technique.insert("technique".into(), parent.into());
                    if !subs.is_empty() {
                        technique.insert(
                            "subTechniques".into(),
                            Json::Array(subs.into_iter().map(Json::from).collect()),
                        );
                    }
                    Json::Object(technique)
                })
                .collect();
            tactic.insert("techniques".into(), Json::Array(techniques));
            Json::Object(tactic)
        })
        .collect();
    (Some(Json::Array(tactics)), warnings)
}

/// The Graph objects of a list of mappings or targets of `kind`, each field
/// sent as its Graph property in the kind's order, a column name verbatim.
fn mapped(kind: &Kind, items: &[Json]) -> Json {
    Json::Array(
        items
            .iter()
            .map(|item| {
                let mut out = Object::new();
                for (field, graph) in kind.fields {
                    let Some(value) = item.get(field).filter(|value| !value.is_null()) else {
                        continue;
                    };
                    let value = if *field == DEVICE_GROUPS {
                        Json::Array(strings(Some(value)).into_iter().map(Json::from).collect())
                    } else {
                        value.clone()
                    };
                    out.insert((*graph).into(), value);
                }
                Json::Object(out)
            })
            .collect(),
    )
}

/// The block's kinds under `key` (`entities` or `actions`), in the table's
/// order, as Graph objects; `None` when none is set.
fn kinds(block: &Json, key: &str, table: &[Kind]) -> Option<Json> {
    let section = block.get(key)?;
    let mut out = Object::new();
    for kind in table {
        if let Some(Json::Array(items)) = section.get(kind.key)
            && !items.is_empty()
        {
            out.insert(kind.graph.into(), mapped(kind, items));
        }
    }
    (!out.is_empty()).then_some(Json::Object(out))
}

/// The Graph `status` of a deployment status: `enabled`, or `disabled` for
/// a DISABLEMENT.
pub fn status(cx: &Context<'_>, block: &Json) -> Result<&'static str, CompileError> {
    let status = block
        .get("status")
        .and_then(Json::as_str)
        .unwrap_or_default();
    Ok(
        if deploy::strategy(cx, DISPLAY, status)? == StatusStrategy::Disablement {
            "disabled"
        } else {
            "enabled"
        },
    )
}

/// The block of `rule`, or the error a rule without one is.
fn block(rule: &Rule) -> Result<&Json, CompileError> {
    rule.block(PLATFORM)
        .filter(|block| block.is_filled())
        .ok_or_else(|| {
            CompileError::invalid_rule(format!(
                "Rule {} ({}): configurations.{PLATFORM} is missing",
                rule.uuid, rule.name
            ))
        })
}

/// A `schedule` duration as Graph takes it.
fn duration(value: &str, field: &str) -> Result<String, CompileError> {
    Duration::parse(value)
        .map(Duration::iso8601)
        .ok_or_else(|| {
            CompileError::failed(
                DISPLAY,
                &format!("schedule.{field} {value:?} is not a duration"),
            )
        })
}

/// The `alertTemplate` of `block`, and the warnings its techniques earned.
fn alert_template(
    cx: &Context<'_>,
    rule: &Rule,
    block: &Json,
) -> Result<(Object, Warnings), CompileError> {
    let alert = block.get("alert").filter(|alert| !alert.is_null());
    let mut template = Object::new();
    template.insert(
        "title".into(),
        text(alert, "title").unwrap_or(&rule.name).into(),
    );
    template.insert(
        "description".into(),
        text(alert, "description")
            .unwrap_or(rule.description())
            .into(),
    );
    let named = text(alert, "severity").or_else(|| {
        rule.response()
            .and_then(|response| response.get("alert_severity"))
            .and_then(Json::as_str)
            .filter(|name| !name.is_empty())
    });
    template.insert(
        "severity".into(),
        severity(named.unwrap_or("Medium"))?.into(),
    );
    if let Some(recommendation) = text(alert, "recommendation") {
        template.insert("recommendedActions".into(), recommendation.into());
    }
    let own = strings(alert.and_then(|alert| alert.get("techniques")));
    let ids = deploy::platform_techniques(cx, DISPLAY, rule, own)?;
    let (tactics, warnings) = tactics(cx, rule, &ids);
    if let Some(tactics) = tactics {
        template.insert("tactics".into(), tactics);
    }
    if let Some(mappings) = kinds(block, "entities", &ENTITY_KINDS) {
        template.insert("entityMappings".into(), mappings);
    }
    if let Some(Json::Object(details)) = alert.and_then(|alert| alert.get("custom_details"))
        && !details.is_empty()
    {
        template.insert("customDetails".into(), Json::Object(details.clone()));
    }
    if let Some(grouping) = text(alert, "grouping") {
        let graph = GROUPINGS
            .iter()
            .find(|(name, _)| *name == grouping)
            .map(|(_, graph)| *graph)
            .ok_or_else(|| {
                CompileError::failed(
                    DISPLAY,
                    &format!("alert.grouping {grouping:?} is not alert_per_event or single_alert"),
                )
            })?;
        template.insert("eventGroupingKind".into(), graph.into());
    }
    Ok((template, warnings))
}

/// The update body `rule` deploys to `tenant` (no `id`), and the warnings it
/// earned.
pub fn body_with_warnings(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: &str,
) -> Result<(Json, Warnings), CompileError> {
    let block = block(rule)?;
    let mut body = Object::new();
    body.insert(
        "displayName".into(),
        text(Some(block), "name").unwrap_or(&rule.name).into(),
    );
    body.insert("description".into(), rule.description().into());
    body.insert("status".into(), status(cx, block)?.into());
    let query = block
        .get("query")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let mut condition = Object::new();
    condition.insert(
        "queryText".into(),
        kql::compile_query(query, block.get("exclusions"), tenant).into(),
    );
    body.insert("queryCondition".into(), Json::Object(condition));
    let schedule = block.get("schedule");
    let mut timing = Object::new();
    timing.insert(
        "frequency".into(),
        duration(text(schedule, "frequency").unwrap_or_default(), "frequency")?.into(),
    );
    if let Some(lookback) = text(schedule, "lookback") {
        timing.insert("lookback".into(), duration(lookback, "lookback")?.into());
    }
    body.insert("schedule".into(), Json::Object(timing));

    let (template, warnings) = alert_template(cx, rule, block)?;
    let mut detection = Object::new();
    detection.insert("alertTemplate".into(), Json::Object(template));
    if let Some(actions) = kinds(block, "actions", &ACTIONS) {
        detection.insert("automatedActions".into(), actions);
    }
    if let Some(groups) = block
        .get("scope")
        .and_then(|scope| scope.get(DEVICE_GROUPS))
        .filter(|groups| groups.is_filled())
    {
        let mut scope = Object::new();
        scope.insert(
            "deviceGroups".into(),
            Json::Array(strings(Some(groups)).into_iter().map(Json::from).collect()),
        );
        detection.insert("organizationalScope".into(), Json::Object(scope));
    }
    if let Some(exclude) = block
        .get("incident")
        .and_then(|incident| incident.get("exclude_from_correlation"))
        .and_then(Json::as_bool)
    {
        let mut incident = Object::new();
        incident.insert(
            "isExcludedFromIncidentCorrelation".into(),
            Json::Bool(exclude),
        );
        detection.insert("incidentConfiguration".into(), Json::Object(incident));
    }
    body.insert("detectionAction".into(), Json::Object(detection));
    Ok((Json::Object(body), warnings))
}

/// The update body of `rule` for `tenant` ([`body_with_warnings`]).
pub fn body(cx: &Context<'_>, rule: &Rule, tenant: &str) -> Result<Json, CompileError> {
    body_with_warnings(cx, rule, tenant).map(|(body, _)| body)
}

/// What every Defender rule id opentide gives a rule starts with (#1886):
/// Graph refuses a rule id that does not begin with a letter, and a UUID
/// begins with a digit ten times in sixteen.
pub const RULE_ID_PREFIX: &str = "opentide-";

/// The Defender rule id of `rule`: [`rule_id_of`] its `metadata.uuid`.
pub fn rule_id(rule: &Rule) -> String {
    rule_id_of(&rule.uuid)
}

/// The Defender rule id of the rule whose `metadata.uuid` is `uuid`:
/// [`RULE_ID_PREFIX`], then the lowercase canonical uuid
/// (`opentide-8f3c4a7e-...`, 45 characters, within Graph's 100). Every
/// request that names a rule (deploy, disable, delete, `--prune`, the dry
/// run's `api_request`) takes its id from here. An id that already starts
/// with the prefix names the same rule, so it is returned as the same id.
pub fn rule_id_of(uuid: &str) -> String {
    format!("{RULE_ID_PREFIX}{}", bare_uuid(uuid))
}

/// The lowercase canonical uuid `id` names, with or without
/// [`RULE_ID_PREFIX`] (any case).
fn bare_uuid(id: &str) -> String {
    let trimmed = id.trim();
    let bare = trimmed
        .split_at_checked(RULE_ID_PREFIX.len())
        .filter(|(head, _)| head.eq_ignore_ascii_case(RULE_ID_PREFIX))
        .map_or(trimmed, |(_, rest)| rest);
    canonical_uuid(bare).to_ascii_lowercase()
}

/// The `metadata.uuid` a Defender rule id names: the lowercase canonical
/// UUID after [`RULE_ID_PREFIX`] (`generate extract defender` imports an
/// opentide rule under its own uuid), only when the id is exactly the one
/// [`rule_id_of`] gives that uuid, as deploy addresses no other; `None` for
/// any other id (`OPENTIDE-<UUID>`, a braced uuid, a bare uuid).
pub fn uuid_of_rule_id(id: &str) -> Option<String> {
    let rest = id.strip_prefix(RULE_ID_PREFIX)?;
    opentide_core::ids::canonical(rest).filter(|canonical| rule_id_of(canonical) == id)
}

/// The create body: `id` first, then the update `body`.
pub fn create_body(id: &str, body: &Json) -> Json {
    let mut out = Object::new();
    out.insert("id".into(), id.into());
    if let Json::Object(fields) = body {
        for (key, value) in fields {
            out.insert(key.clone(), value.clone());
        }
    }
    Json::Object(out)
}

/// `{base}/{id}`, for a Defender rule id ([`rule_id_of`]).
pub fn rule_url(id: &str) -> String {
    format!("{ENDPOINT}/{id}")
}

/// The first call a deploy of `rule` to `tenant` makes (microsoft-defender-1.0,
/// Deploy): `PATCH {base}/{id}` with the body for an active or DISABLEMENT
/// status, `DELETE {base}/{id}` for a DELETION, none for an INERT one, `id`
/// being the rule's [`rule_id`]. The `POST` a `404` leads to is not shown: a
/// dry run reaches no tenant.
pub fn compile(cx: &Context<'_>, rule: &Rule, tenant: &str) -> Result<Vec<Write>, CompileError> {
    let block = block(rule)?;
    let status = block
        .get("status")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let id = rule_id(rule);
    Ok(match deploy::strategy(cx, DISPLAY, status)? {
        StatusStrategy::Inert => Vec::new(),
        StatusStrategy::Deletion => vec![Write::new("DELETE", rule_url(&id), Json::Null)],
        _ => vec![Write::new("PATCH", rule_url(&id), body(cx, rule, tenant)?)],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_is_high() {
        assert_eq!(severity("Critical").unwrap(), "high");
        assert_eq!(severity("Informational").unwrap(), "informational");
        assert!(severity("Severe").is_err());
    }

    #[test]
    fn every_severity_the_model_accepts_compiles() {
        for name in opentide_schema::objects::platform::SEVERITIES {
            assert!(severity(name).is_ok(), "{name}");
            assert!(severity(&name.to_lowercase()).is_err(), "{name}");
        }
    }

    #[test]
    fn stages_rank_in_graphs_order_and_fold_defense_evasion() {
        assert_eq!(tactic_rank("Initial Access"), Some(2));
        assert_eq!(tactic_rank("stealth"), tactic_rank("Defense Impairment"));
        assert_eq!(tactic_rank("Defense Evasion"), tactic_rank("Stealth"));
        assert_eq!(TACTICS[tactic_rank("Stealth").unwrap()].1, "DefenseEvasion");
        assert_eq!(
            tactic_rank("Command and Control").map(|r| TACTICS[r].1),
            Some("CommandAndControl")
        );
        assert_eq!(tactic_rank("Inhibit Response Function"), None);
    }

    #[test]
    fn the_rule_id_starts_with_a_letter_whatever_the_uuid() {
        // #1886: Graph refuses an id that begins with a digit.
        for (uuid, id) in [
            (
                "8F3C4A7E-0000-4000-8000-000000000001",
                "opentide-8f3c4a7e-0000-4000-8000-000000000001",
            ),
            (
                " ff19aaaa-0000-4000-8000-000000000001 ",
                "opentide-ff19aaaa-0000-4000-8000-000000000001",
            ),
            (
                "{2594bf5e000040008000000000000001}",
                "opentide-2594bf5e-0000-4000-8000-000000000001",
            ),
            // An id already given names the same rule.
            (
                "OPENTIDE-2594BF5E-0000-4000-8000-000000000001",
                "opentide-2594bf5e-0000-4000-8000-000000000001",
            ),
        ] {
            assert_eq!(rule_id_of(uuid), id, "{uuid}");
            assert!(id.len() <= 100);
            assert_eq!(
                uuid_of_rule_id(id).as_deref(),
                id.strip_prefix(RULE_ID_PREFIX)
            );
        }
    }

    #[test]
    fn only_the_id_deploy_gives_a_rule_names_its_uuid() {
        // #1886: any other form of the id is not the rule deploy addresses.
        for id in [
            "8f3c4a7e-0000-4000-8000-000000000001",
            "OPENTIDE-8F3C4A7E-0000-4000-8000-000000000001",
            "opentide-8F3C4A7E-0000-4000-8000-000000000001",
            "Opentide-8f3c4a7e-0000-4000-8000-000000000001",
            "opentide-{8f3c4a7e-0000-4000-8000-000000000001}",
            "opentide-8f3c4a7e000040008000000000000001",
            " opentide-8f3c4a7e-0000-4000-8000-000000000001",
            "opentide-8f3c4a7e-0000-4000-8000-000000000001 ",
            "opentide-7506",
            "opentide-",
            "7506",
        ] {
            assert_eq!(uuid_of_rule_id(id), None, "{id}");
        }
        assert_eq!(
            uuid_of_rule_id("opentide-8f3c4a7e-0000-4000-8000-000000000001").as_deref(),
            Some("8f3c4a7e-0000-4000-8000-000000000001")
        );
    }

    #[test]
    fn the_create_body_puts_the_id_first() {
        let mut body = Object::new();
        body.insert("displayName".into(), "x".into());
        assert_eq!(
            create_body("00000000-0000-4000-8000-000000000001", &Json::Object(body)).to_compact(),
            r#"{"id":"00000000-0000-4000-8000-000000000001","displayName":"x"}"#
        );
    }

    #[test]
    fn a_multi_byte_character_where_the_prefix_would_end_is_no_prefix() {
        // #1946: the prefix is split off only on a char boundary.
        for id in ["opentid😀x", "opentidé", "😀", "é-8f3c4a7e"] {
            assert_eq!(
                rule_id_of(id),
                format!(
                    "{RULE_ID_PREFIX}{}",
                    canonical_uuid(id.trim()).to_ascii_lowercase()
                ),
                "{id}"
            );
            assert_eq!(uuid_of_rule_id(id), None, "{id}");
        }
    }
}
