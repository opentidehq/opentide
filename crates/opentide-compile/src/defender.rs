//! Microsoft Defender for Endpoint: the custom detection rule a deploy sends
//! to one tenant through Microsoft Graph (`platforms/defender_for_endpoint/
//! deployer.py` `deploy_mdr`, the client's `create_detection_rule`,
//! `update_detection_rule`, `delete_detection_rule`).

use crate::Context;
use crate::deploy::{self, Action, Write};
use crate::json::{Json, Object};
use crate::kql;
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;

/// The platform's key under `configurations`.
pub const PLATFORM: &str = "defender_for_endpoint";

/// The platform's display name, in messages.
pub const DISPLAY: &str = "Defender for Endpoint";

/// The detection rules collection of Microsoft Graph.
pub const ENDPOINT: &str = "https://graph.microsoft.com/beta/security/rules/detectionRules";

/// `string` with its first character lowercased (`lower_first_character`).
fn lower_first(string: &str) -> String {
    let mut chars = string.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// A string the block sets, Python-truthy.
fn text<'j>(value: Option<&'j Json>, key: &str) -> Option<&'j str> {
    value
        .and_then(|value| value.get(key))
        .and_then(Json::as_str)
        .filter(|text| !text.is_empty())
}

/// Whether the block sets `key` to a Python-truthy value.
fn set(value: Option<&Json>, key: &str) -> bool {
    value
        .and_then(|value| value.get(key))
        .is_some_and(Json::truthy)
}

/// A response action (`ResponseAction`): `@odata.type` and `identifier`.
fn response_action(odata: &str, identifier: Json) -> Object {
    let mut action = Object::new();
    action.insert("@odata.type".into(), odata.into());
    action.insert("identifier".into(), identifier);
    action
}

fn graph(kind: &str) -> String {
    format!("#microsoft.graph.security.{kind}")
}

/// The response actions of the block's `actions`, in the deployer's order.
fn response_actions(actions: Option<&Json>) -> Vec<Json> {
    let mut out: Vec<Json> = Vec::new();
    let Some(actions) = actions.filter(|actions| actions.truthy()) else {
        return out;
    };
    let device = || Json::Str("deviceId".into());
    if let Some(devices) = actions.get("devices").filter(|value| value.truthy()) {
        if let Some(isolation) = text(Some(devices), "isolate_device") {
            let mut action = response_action(&graph("isolateDeviceResponseAction"), device());
            action.insert("isolationType".into(), lower_first(isolation).into());
            out.push(Json::Object(action));
        }
        for (key, kind) in [
            (
                "collect_investigation_package",
                "collectInvestigationPackageResponseAction",
            ),
            (
                "initiate_investigation",
                "initiateInvestigationResponseAction",
            ),
            (
                "restrict_app_execution",
                "restrictAppExecutionResponseAction",
            ),
            ("run_antivirus_scan", "runAntivirusScanResponseAction"),
        ] {
            if set(Some(devices), key) {
                out.push(Json::Object(response_action(&graph(kind), device())));
            }
        }
    }
    if let Some(files) = actions.get("files").filter(|value| value.truthy()) {
        if let Some(allow_block) = files.get("allow_block").filter(|value| value.truthy()) {
            let identifier = allow_block
                .get("identifier")
                .and_then(Json::as_str)
                .unwrap_or_default();
            let mut scope = Json::Array(Vec::new());
            if let Some(groups) = allow_block.get("groups").filter(|value| value.truthy())
                && groups.get("selection").and_then(Json::as_str) == Some("Specific")
            {
                scope = groups.get("device_groups").cloned().unwrap_or(Json::Null);
            }
            let kind = match allow_block.get("action").and_then(Json::as_str) {
                Some("Allow") => Some("allowFileResponseAction"),
                Some("Block") => Some("blockFileResponseAction"),
                _ => None,
            };
            if let Some(kind) = kind {
                let mut action = response_action(&graph(kind), lower_first(identifier).into());
                action.insert("deviceGroupNames".into(), scope);
                out.push(Json::Object(action));
            }
        }
        if let Some(identifier) = files.get("quarantine_file").filter(|value| value.truthy()) {
            out.push(Json::Object(response_action(
                &graph("stopAndQuarantineFileResponseAction"),
                identifier.clone(),
            )));
        }
    }
    if let Some(users) = actions.get("users").filter(|value| value.truthy()) {
        for (key, kind) in [
            ("mark_as_compromised", "markUserAsCompromisedResponseAction"),
            ("disable_user", "disableUserResponseAction"),
            (
                "force_password_reset",
                "forceUserPasswordResetResponseAction",
            ),
        ] {
            if let Some(identifier) = text(Some(users), key) {
                out.push(Json::Object(response_action(
                    &graph(kind),
                    lower_first(identifier).into(),
                )));
            }
        }
    }
    out
}

/// The impacted assets of `impacted_entities`: device, user, mailbox.
fn impacted_assets(entities: Option<&Json>) -> Vec<Json> {
    let mut out = Vec::new();
    for (key, kind) in [
        ("device", "impactedDeviceAsset"),
        ("user", "impactedUserAsset"),
        ("mailbox", "impactedMailboxAsset"),
    ] {
        if let Some(identifier) = text(entities, key) {
            out.push(Json::Object(response_action(
                &graph(kind),
                lower_first(identifier).into(),
            )));
        }
    }
    out
}

/// Defender's severity of an opentide severity (`SeverityMapping`):
/// Critical is `high`.
fn severity(name: &str) -> Result<&'static str, CompileError> {
    Ok(match name {
        "Informational" => "informational",
        "Low" => "low",
        "Medium" => "medium",
        "High" | "Critical" => "high",
        other => return Err(CompileError::failed(DISPLAY, &format!("{other:?}"))),
    })
}

/// The detection rule body `rule` deploys to `tenant` (`DetectionRule`, as
/// the client sends it: `@odata.type` for `odata_type`).
pub fn body(cx: &Context<'_>, rule: &Rule, tenant: &str) -> Result<Json, CompileError> {
    let Some(block) = rule.block(PLATFORM).filter(|block| block.truthy()) else {
        return Err(CompileError::invalid_rule(format!(
            "Rule {} ({}): configurations.{PLATFORM} is missing",
            rule.uuid, rule.name
        )));
    };
    let alert = block.get("alert");
    let severity = match text(alert, "severity") {
        Some(name) => severity(name)?,
        None if rule.response().is_some() => severity(rule.alert_severity())?,
        None => severity("Informational")?,
    };
    let category = alert
        .and_then(|alert| alert.get("category"))
        .and_then(Json::as_str)
        .unwrap_or_default()
        .replace(' ', "");
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
    template.insert("severity".into(), severity.into());
    template.insert("category".into(), category.into());
    template.insert("mitreTechniques".into(), Json::Array(Vec::new()));
    template.insert(
        "impactedAssets".into(),
        Json::Array(impacted_assets(block.get("impacted_entities"))),
    );
    template.insert(
        "recommendedActions".into(),
        text(alert, "recommendation").map_or(Json::Null, Json::from),
    );
    let scheduling = block
        .get("scheduling")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let period = if scheduling == "NRT" { "0" } else { scheduling };
    let status = block
        .get("status")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let enabled = deploy::strategy(cx, DISPLAY, status)? != StatusStrategy::Disablement;
    let query = block
        .get("query")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let mut condition = Object::new();
    condition.insert(
        "queryText".into(),
        kql::compile_query(query, block.get("exclusions"), tenant).into(),
    );
    let mut schedule = Object::new();
    schedule.insert("period".into(), period.into());
    let mut detection = Object::new();
    detection.insert("alertTemplate".into(), Json::Object(template));
    detection.insert(
        "responseActions".into(),
        Json::Array(response_actions(block.get("actions"))),
    );
    detection.insert("organizationalScope".into(), Json::Null);
    let mut body = Object::new();
    body.insert("displayName".into(), rule.name.clone().into());
    body.insert("queryCondition".into(), Json::Object(condition));
    body.insert("schedule".into(), Json::Object(schedule));
    body.insert("detectionAction".into(), Json::Object(detection));
    body.insert("isEnabled".into(), Json::Bool(enabled));
    Ok(Json::Object(body))
}

/// The writes a deploy sends for `rule` to `tenant`, whose recorded id is
/// `known`: a create (`POST`), an update (`PATCH`) or a delete (`DELETE`),
/// or none for a rule to retire that the tenant never received.
pub fn compile(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: &str,
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
    Ok(vec![match action {
        Action::Create => Write::new("POST", ENDPOINT, body),
        Action::Update(id) => Write::new("PATCH", format!("{ENDPOINT}/{id}"), body),
        Action::Delete(id) => Write::new("DELETE", format!("{ENDPOINT}/{id}"), Json::Null),
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_characters_are_lowercased() {
        assert_eq!(lower_first("DeviceId"), "deviceId");
        assert_eq!(lower_first("SHA1"), "sHA1");
        assert_eq!(lower_first(""), "");
    }

    #[test]
    fn critical_is_high() {
        assert_eq!(severity("Critical").unwrap(), "high");
        assert_eq!(severity("Informational").unwrap(), "informational");
        assert_eq!(
            severity("Severe").unwrap_err().reason,
            "Defender for Endpoint cannot compile this rule: 'Severe'"
        );
    }
}
