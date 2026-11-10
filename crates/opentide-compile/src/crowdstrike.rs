//! CrowdStrike Falcon: the correlation rule a deploy sends to one tenant
//! (`platforms/crowdstrike/deployer.py` `compile_deployment`, the client's
//! `create_detection_rule`, `update_detection_rule` and
//! `delete_detection_rule`): the body with its `null` values left out.

use crate::Context;
use crate::deploy::{self, Action, Write};
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::sentinel_one::without_nulls;
use crate::strategy::StatusStrategy;

/// The platform's key under `configurations`.
pub const PLATFORM: &str = "crowdstrike";

/// The platform's display name, in messages.
pub const DISPLAY: &str = "CrowdStrike";

/// The API of a tenant's `api` cloud (`_get_base_api`).
pub fn base_api(domain: &str) -> Result<&'static str, CompileError> {
    Ok(match domain {
        "US-1" => "https://api.crowdstrike.com",
        "US-2" => "https://api.us-2.crowdstrike.com",
        "EU-1" => "https://api.eu-1.crowdstrike.com",
        "US-GOV-1" => "https://api.laggar.gcw.crowdstrike.com",
        "US-GOV-2" => "https://api.falcon.us-gov-2.crowdstrike.mil",
        _ => return Err(CompileError::failed(DISPLAY, "Invalid API Domain")),
    })
}

/// CrowdStrike's severity of an opentide severity (`map_severity`).
fn severity(name: &str) -> Result<i64, CompileError> {
    Ok(match name {
        "Informational" => 10,
        "Low" => 30,
        "Medium" => 50,
        "High" => 70,
        "Critical" => 90,
        _ => return Err(CompileError::failed(DISPLAY, "Invalid Severity")),
    })
}

/// A timestamp as the API takes it (`fix_datetime`): one without `Z` is
/// read as `2025-04-15 19:00:00+00:00` and written `2025-04-15T19:00:00Z`.
pub fn fix_datetime(timestamp: &str) -> String {
    if timestamp.contains('Z') {
        return timestamp.to_owned();
    }
    let joined = timestamp.replace(' ', "T");
    let head = joined.split('+').next().unwrap_or_default();
    format!("{head}Z")
}

/// A value the block sets, Python-truthy.
fn truthy<'j>(value: Option<&'j Json>, key: &str) -> Option<&'j Json> {
    value
        .and_then(|value| value.get(key))
        .filter(|value| value.truthy())
}

fn string<'j>(value: Option<&'j Json>, key: &str) -> &'j str {
    value
        .and_then(|value| value.get(key))
        .and_then(Json::as_str)
        .unwrap_or_default()
}

fn member(value: Option<&Json>, key: &str) -> Json {
    value
        .and_then(|value| value.get(key))
        .cloned()
        .unwrap_or(Json::Null)
}

/// The correlation rule body `rule` deploys to `tenant`, `null` values left
/// out.
pub fn body(cx: &Context<'_>, rule: &Rule, tenant: &Json) -> Result<Json, CompileError> {
    let Some(block) = rule.block(PLATFORM).filter(|block| block.truthy()) else {
        return Err(CompileError::failed(DISPLAY, "Missing Crowdstrike Section"));
    };
    let details = block.get("details");
    let schedule = block.get("schedule");
    let name = truthy(details, "name")
        .cloned()
        .unwrap_or_else(|| rule.name.clone().into());
    let description = truthy(details, "description")
        .cloned()
        .unwrap_or_else(|| rule.description().into());
    let customer_id = deploy::setup_text(tenant, "customer_id")
        .split('-')
        .next()
        .unwrap_or_default()
        .to_lowercase();
    let status = block
        .get("status")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let rule_status = if deploy::strategy(cx, DISPLAY, status)? == StatusStrategy::Disablement {
        "inactive"
    } else {
        "active"
    };
    let severity = severity(
        truthy(details, "severity")
            .and_then(Json::as_str)
            .unwrap_or(rule.alert_severity()),
    )?;
    let outcome = string(details, "outcome").to_lowercase();
    let trigger_mode = string(details, "trigger").to_lowercase();
    if !matches!(outcome.as_str(), "detection" | "incident")
        || !matches!(trigger_mode.as_str(), "verbose" | "summary")
    {
        // The oracle says `outcome` for a bad trigger too.
        return Err(CompileError::failed(
            DISPLAY,
            "Invalid Crowdstrike outcome value",
        ));
    }
    let mut search = Object::new();
    search.insert("outcome".into(), outcome.into());
    search.insert("filter".into(), member(Some(block), "query"));
    search.insert("lookback".into(), member(schedule, "lookback"));
    search.insert("trigger_mode".into(), trigger_mode.into());
    let mut definition = Object::new();
    definition.insert(
        "definition".into(),
        format!(
            "@every {}",
            schedule
                .and_then(|schedule| schedule.get("frequency"))
                .map(deploy::text)
                .unwrap_or_default()
        )
        .into(),
    );
    let mut operation = Object::new();
    operation.insert("schedule".into(), Json::Object(definition));
    for (from, to) in [("start", "start_on"), ("end", "stop_on")] {
        operation.insert(
            to.into(),
            truthy(schedule, from).map_or(Json::Null, |value| {
                fix_datetime(&deploy::text(value)).into()
            }),
        );
    }
    let authors: Vec<String> = match truthy(Some(block), "contributors") {
        Some(Json::Array(items)) => items
            .iter()
            .filter(|item| item.truthy())
            .map(deploy::text)
            .collect(),
        _ => deploy::rule_text(rule, &["metadata", "author"])
            .map(str::to_owned)
            .into_iter()
            .collect(),
    };
    let mut body = Object::new();
    body.insert("name".into(), name);
    body.insert("description".into(), description);
    body.insert("customer_id".into(), customer_id.into());
    body.insert("severity".into(), Json::Int(severity));
    body.insert("search".into(), Json::Object(search));
    body.insert("operation".into(), Json::Object(operation));
    body.insert("status".into(), rule_status.into());
    body.insert("tactic".into(), member(details, "tactic"));
    body.insert("technique".into(), member(details, "technique"));
    body.insert(
        "comment".into(),
        format!(
            "Updated by opentide Crowdstrike Deployer - Author(s) : {}",
            authors.join(", ")
        )
        .into(),
    );
    Ok(without_nulls(Json::Object(body)))
}

/// The writes a deploy sends for `rule` to `tenant`, whose recorded id is
/// `known`: a create (`POST`), an update (`PATCH` of a one-rule list with
/// the id) or a delete (`DELETE ?ids=`), or none for a rule to retire that
/// the tenant never received.
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
    // The client, which names the cloud, is built before the body.
    let endpoint = format!(
        "{}/correlation-rules/entities/rules/v1",
        base_api(&deploy::setup_text(tenant, "api"))?
    );
    let body = body(cx, rule, tenant)?;
    Ok(vec![match action {
        Action::Create => Write::new("POST", endpoint, body),
        Action::Update(id) => {
            let mut body = body;
            if let Json::Object(object) = &mut body {
                object.insert("id".into(), id.into());
            }
            Write::new("PATCH", endpoint, Json::Array(vec![body]))
        }
        Action::Delete(id) => {
            let query: String = form_urlencoded::Serializer::new(String::new())
                .append_pair("ids", &id)
                .finish();
            Write::new("DELETE", format!("{endpoint}?{query}"), Json::Null)
        }
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_end_in_z() {
        assert_eq!(fix_datetime("2025-04-15T19:00:00Z"), "2025-04-15T19:00:00Z");
        assert_eq!(
            fix_datetime("2025-04-15 19:00:00+00:00"),
            "2025-04-15T19:00:00Z"
        );
    }

    #[test]
    fn clouds_and_severities() {
        assert_eq!(
            base_api("EU-1").unwrap(),
            "https://api.eu-1.crowdstrike.com"
        );
        assert!(base_api("EU-2").is_err());
        assert_eq!(severity("High").unwrap(), 70);
        assert!(severity("Severe").is_err());
    }
}
