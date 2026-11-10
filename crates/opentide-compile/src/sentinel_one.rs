//! SentinelOne: the STAR custom detection rule a deploy sends to one tenant
//! (`platforms/sentinel_one/deployer.py` `compile_deployment`, the client's
//! `create_update_detection_rule` and `delete_detection_rule`): the body with
//! its `null` values left out.

use crate::Context;
use crate::deploy::{self, Action, Write};
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::strategy::{StatusStrategy, python_repr};

/// The platform's key under `configurations`.
pub const PLATFORM: &str = "sentinel_one";

/// The platform's display name, in messages.
pub const DISPLAY: &str = "SentinelOne";

/// A failure the oracle raises without a message (`raise Exception`).
fn bare() -> CompileError {
    CompileError::failed(DISPLAY, "")
}

/// A duration in minutes (`_convert_to_minutes`): `30m`, or `2h`.
pub fn minutes(timespan: &str) -> Result<i64, CompileError> {
    let refused = || {
        CompileError::failed(
            DISPLAY,
            &format!(
                "SentinelOne expects a duration in minutes (30m) or hours (2h), got {}",
                python_repr(timespan)
            ),
        )
    };
    let (count, factor) = if let Some(count) = timespan.strip_suffix('m') {
        (count, 1)
    } else if let Some(count) = timespan.strip_suffix('h') {
        (count, 60)
    } else {
        return Err(refused());
    };
    count
        .trim()
        .parse::<i64>()
        .ok()
        .and_then(|count| count.checked_mul(factor))
        .ok_or_else(refused)
}

/// SentinelOne's severity of an opentide severity (`SeverityMapping`):
/// Informational is `Low`.
fn severity(name: &str) -> Result<&'static str, CompileError> {
    Ok(match name {
        "Informational" | "Low" => "Low",
        "Medium" => "Medium",
        "High" => "High",
        "Critical" => "Critical",
        other => return Err(CompileError::failed(DISPLAY, &python_repr(other))),
    })
}

/// A string the block sets, Python-truthy.
fn text<'j>(value: Option<&'j Json>, key: &str) -> Option<&'j str> {
    value
        .and_then(|value| value.get(key))
        .and_then(Json::as_str)
        .filter(|text| !text.is_empty())
}

/// `value` without its `null` members and items (`_remove_nulls`).
pub fn without_nulls(value: Json) -> Json {
    match value {
        Json::Object(object) => Json::Object(
            object
                .into_iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key, without_nulls(value)))
                .collect(),
        ),
        Json::Array(items) => Json::Array(
            items
                .into_iter()
                .filter(|value| !value.is_null())
                .map(without_nulls)
                .collect(),
        ),
        other => other,
    }
}

/// The rule body `rule` deploys to `tenant` (`DetectionRule`: `data` and
/// `filter`), `null` values left out.
pub fn body(cx: &Context<'_>, rule: &Rule, tenant: &Json) -> Result<Json, CompileError> {
    let Some(block) = rule.block(PLATFORM).filter(|block| block.truthy()) else {
        return Err(bare());
    };
    let mut name = Json::Str(rule.name.clone());
    let mut description = Json::Str(rule.description().to_owned());
    let mut expiration_mode = "Permanent";
    let mut rule_severity = Json::Str(severity(rule.alert_severity())?.to_owned());
    let mut expiration = Json::Null;
    let status = block
        .get("status")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let rule_status = if deploy::strategy(cx, DISPLAY, status)? == StatusStrategy::Disablement {
        "Disabled"
    } else {
        "Active"
    };
    if let Some(details) = block.get("details").filter(|details| details.truthy()) {
        if let Some(value) = details.get("name").filter(|value| value.truthy()) {
            name = value.clone();
        }
        if let Some(value) = details.get("description").filter(|value| value.truthy()) {
            description = value.clone();
        }
        if let Some(value) = details.get("severity").filter(|value| value.truthy()) {
            rule_severity = value.clone();
        }
        if let Some(value) = details.get("expiration").filter(|value| value.truthy()) {
            expiration_mode = "Temporary";
            expiration = value.clone();
        }
    }
    let (treat_as_threat, network_quarantine) =
        match block.get("response").filter(|response| response.truthy()) {
            Some(response) => {
                let treat = match response.get("treat_as_threat") {
                    Some(Json::Bool(false)) => Json::Str("UNDEFINED".into()),
                    Some(value) => value.clone(),
                    None => Json::Null,
                };
                (
                    treat,
                    response
                        .get("network_quarantine")
                        .cloned()
                        .unwrap_or(Json::Null),
                )
            }
            None => (Json::Null, Json::Null),
        };
    let condition = block.get("condition");
    let mut cool_off = Json::Null;
    if let Some(span) = text(condition, "cool_off") {
        let mut settings = Object::new();
        settings.insert("renotifyMinutes".into(), Json::Int(minutes(span)?));
        cool_off = Json::Object(settings);
    }
    let kind = condition
        .and_then(|condition| condition.get("type"))
        .and_then(Json::as_str);
    let mut data = Object::new();
    data.insert("expirationMode".into(), expiration_mode.into());
    data.insert("name".into(), name);
    data.insert("description".into(), description);
    let mut s1ql = Json::Null;
    let mut correlation_params = Json::Null;
    match kind {
        Some("Single Event") => {
            let Some(single) = condition
                .and_then(|condition| condition.get("single_event"))
                .filter(|single| single.truthy())
            else {
                return Err(bare());
            };
            data.insert("queryType".into(), "events".into());
            s1ql = single.get("query").cloned().unwrap_or(Json::Null);
        }
        Some("Correlation") => {
            let Some(correlation) = condition
                .and_then(|condition| condition.get("correlation"))
                .filter(|correlation| correlation.truthy())
            else {
                return Err(bare());
            };
            let mut sub_queries = Vec::new();
            if let Some(Json::Array(items)) = correlation.get("sub_queries") {
                for item in items {
                    let mut sub = Object::new();
                    sub.insert(
                        "matchesRequired".into(),
                        item.get("matches_required").cloned().unwrap_or(Json::Null),
                    );
                    sub.insert(
                        "subQuery".into(),
                        item.get("query").cloned().unwrap_or(Json::Null),
                    );
                    sub_queries.push(Json::Object(sub));
                }
            }
            let mut window = Json::Null;
            if let Some(span) = text(Some(correlation), "time_window") {
                let mut settings = Object::new();
                settings.insert("windowMinutes".into(), Json::Int(minutes(span)?));
                window = Json::Object(settings);
            }
            let mut params = Object::new();
            params.insert(
                "entity".into(),
                correlation.get("entity").cloned().unwrap_or(Json::Null),
            );
            params.insert(
                "matchInOrder".into(),
                correlation
                    .get("match_in_order")
                    .cloned()
                    .unwrap_or(Json::Null),
            );
            params.insert("subQueries".into(), Json::Array(sub_queries));
            params.insert("timeWindow".into(), window);
            data.insert("queryType".into(), "correlation".into());
            correlation_params = Json::Object(params);
        }
        _ => return Err(bare()),
    }
    data.insert("severity".into(), rule_severity);
    data.insert("status".into(), rule_status.into());
    data.insert("networkQuarantine".into(), network_quarantine);
    data.insert("treatAsThreat".into(), treat_as_threat);
    data.insert("queryLang".into(), "2.0".into());
    data.insert("s1ql".into(), s1ql);
    data.insert("expiration".into(), expiration);
    data.insert("coolOffSetting".into(), cool_off);
    data.insert("correlationParams".into(), correlation_params);
    let mut filter = Object::new();
    if let Some(site) = deploy::setup(tenant, "site_id").filter(|site| site.truthy()) {
        filter.insert("accountIds".into(), Json::Null);
        filter.insert(
            "siteIds".into(),
            Json::Array(vec![Json::Str(deploy::text(site))]),
        );
    } else if let Some(account) = deploy::setup(tenant, "account_id").filter(|id| id.truthy()) {
        filter.insert(
            "accountIds".into(),
            Json::Array(vec![Json::Str(deploy::text(account))]),
        );
        filter.insert("siteIds".into(), Json::Null);
    } else {
        return Err(CompileError::failed(
            DISPLAY,
            "the tenant sets neither site_id nor account_id",
        ));
    }
    let mut body = Object::new();
    body.insert("data".into(), Json::Object(data));
    body.insert("filter".into(), Json::Object(filter));
    Ok(without_nulls(Json::Object(body)))
}

/// The id the deployment state records, as the deployer reads it (`int()`).
fn numeric(id: &str) -> Result<i64, CompileError> {
    id.trim().parse::<i64>().map_err(|_| {
        CompileError::failed(
            DISPLAY,
            &format!(
                "invalid literal for int() with base 10: {}",
                python_repr(id)
            ),
        )
    })
}

/// The writes a deploy sends for `rule` to `tenant`, whose recorded id is
/// `known`: a create (`POST`), an update (`PUT`) or a delete (`DELETE` with
/// a filter on the id), or none for a rule to retire that the tenant never
/// received.
pub fn compile(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: &Json,
    known: Option<&str>,
) -> Result<Vec<Write>, CompileError> {
    let status = rule
        .block(PLATFORM)
        .and_then(|block| block.get("status"))
        .and_then(Json::as_str)
        .unwrap_or_default();
    let Some(action) = deploy::action(cx, DISPLAY, status, known)? else {
        return Ok(Vec::new());
    };
    let body = body(cx, rule, tenant)?;
    let endpoint = format!(
        "{}/web/api/v2.1/cloud-detection/rules",
        deploy::setup_text(tenant, "url")
    );
    Ok(vec![match action {
        Action::Create => Write::new("POST", endpoint, body),
        Action::Update(id) => Write::new("PUT", format!("{endpoint}/{}", numeric(&id)?), body),
        Action::Delete(id) => {
            let mut ids = Object::new();
            ids.insert("ids".into(), Json::Array(vec![Json::Int(numeric(&id)?)]));
            let mut filter = Object::new();
            filter.insert("filter".into(), Json::Object(ids));
            Write::new("DELETE", endpoint, Json::Object(filter))
        }
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_minutes() {
        assert_eq!(minutes("30m").unwrap(), 30);
        assert_eq!(minutes("2h").unwrap(), 120);
        assert_eq!(
            minutes("30s").unwrap_err().reason,
            "SentinelOne cannot compile this rule: SentinelOne expects a duration in minutes \
             (30m) or hours (2h), got '30s'"
        );
        assert!(minutes("xm").is_err());
    }

    #[test]
    fn nulls_are_left_out_at_every_depth() {
        let value: Json =
            serde_json::from_str(r#"{"a":null,"b":[null,{"c":null,"d":1}],"e":false}"#).unwrap();
        assert_eq!(
            without_nulls(value).to_compact(),
            r#"{"b":[{"d":1}],"e":false}"#
        );
    }

    #[test]
    fn informational_is_low() {
        assert_eq!(severity("Informational").unwrap(), "Low");
        assert_eq!(severity("Critical").unwrap(), "Critical");
        assert!(severity("x").is_err());
    }
}
