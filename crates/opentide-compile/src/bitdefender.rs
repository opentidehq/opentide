//! The Bitdefender GravityZone JSON-RPC params (bitdefender-1.0, Deploy;
//! 0.28.0's `platforms/bitdefender/compile.py`): what a block deploys,
//! derived from the rule (the GravityZone name, description, severity and
//! tags) and the tenant (targets, tags, the partner company), as the
//! `params` of `createCustomRule`, `updateCustomRule` and `deleteCustomRule`.
//!
//! Every update carries the whole payload, because GravityZone keeps the
//! stored value of any optional parameter it is not sent: no `alert` sends
//! `filters: []`, no targets sends `targets: {}`. Every call carries
//! `type: 1`, a detection rule: exclusion rules (`type: 2`) are never sent.

use opentide_schema::objects::platform::bitdefender::checks::targets_shape_ok_json;
use opentide_schema::objects::platform::bitdefender::{
    ACTION_TYPES, BitdefenderActions, BitdefenderConfig, Kind, NOT_ON_YARA, ProcessAction,
    ScanType, cut, gravityzone_name, normalise,
};
use opentide_schema::objects::platform::is_python_space;

use crate::Context;
use crate::deploy::{Action, setup};
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;

/// The platform's identifier.
pub const PLATFORM: &str = "bitdefender";

/// The platform's display name, in a failure's message.
pub const DISPLAY: &str = "Bitdefender GravityZone";

/// Every call's `type`: a detection rule.
pub const RULE_TYPE: i64 = 1;

/// `createCustomRule`.
pub const CREATE: &str = "createCustomRule";
/// `updateCustomRule`.
pub const UPDATE: &str = "updateCustomRule";
/// `deleteCustomRule`.
pub const DELETE: &str = "deleteCustomRule";

/// The severity of a rule whose block and response name none: Medium.
pub const DEFAULT_SEVERITY: i64 = 2;

/// The longest description; a longer one is cut with a trailing `…`.
pub const DESCRIPTION_LIMIT: usize = 1024;
/// The longest tag.
pub const TAG_LIMIT: usize = 128;
/// The shortest tag.
pub const TAG_MINIMUM: usize = 2;

/// `bitdefender_target_unknown`: an alias the tenant's tables do not hold.
pub const TARGET_UNKNOWN: &str = "bitdefender_target_unknown";
/// `bitdefender_targets_shape`: targets that hold no alias.
pub const TARGETS_SHAPE: &str = "bitdefender_targets_shape";

/// `response.alert_severity` → `settings.severity` (bitdefender-1.0, Severity).
fn alert_severity(severity: &str) -> Option<i64> {
    match severity {
        "critical" | "high" => Some(3),
        "medium" => Some(2),
        "low" | "informational" => Some(1),
        _ => None,
    }
}

/// What a block deploys on one tenant, after derivation (`GravityZoneRule`).
#[derive(Debug, Clone, PartialEq)]
pub struct GravityZoneRule {
    /// The rule's UUID.
    pub uuid: String,
    /// A Basic or a YARA rule.
    pub kind: Kind,
    /// The GravityZone name.
    pub name: String,
    /// The description.
    pub description: String,
    /// The tags.
    pub tags: Vec<String>,
    /// `settings`.
    pub settings: Object,
    /// `targets`, resolved against the tenant; `None` for the whole company.
    pub targets: Option<Json>,
    /// The partner company that owns created rules.
    pub company_id: Option<String>,
}

/// A `targets` the tenant cannot resolve (`BitdefenderTargetError`): an
/// unknown alias, or no alias at all. A deploy reports it, and a dry run's
/// compile diagnostic reads it, under the same code.
pub fn target_error(code: &'static str, reason: &str, tenant: Option<&str>) -> CompileError {
    let reason = match tenant {
        Some(tenant) => format!("tenant {tenant:?}: {reason}"),
        None => reason.to_owned(),
    };
    let hint = if code == TARGET_UNKNOWN {
        "add the alias to the tenant's endpoint_tags or companies table, or change the block's \
         targets"
    } else {
        "set exactly one of endpoint_tags and companies, or leave targets out"
    };
    CompileError::new(code, reason, Some(hint))
}

fn block_json(rule: &Rule) -> Result<&Json, CompileError> {
    rule.block(PLATFORM).ok_or_else(|| {
        CompileError::failed(
            DISPLAY,
            &format!(
                "Rule {} ({}) has no bitdefender block",
                rule.uuid, rule.name
            ),
        )
    })
}

/// The rule's Bitdefender block, read by its model (`block_of`).
pub fn block_of(rule: &Rule) -> Result<BitdefenderConfig, CompileError> {
    let value = serde_json::to_value(block_json(rule)?)
        .map_err(|error| CompileError::failed(DISPLAY, &error.to_string()))?;
    serde_json::from_value(value).map_err(|error| CompileError::failed(DISPLAY, &error.to_string()))
}

/// The strategy the block's status maps to (`_strategy`).
pub fn strategy(cx: &Context<'_>, rule: &Rule) -> Result<StatusStrategy, CompileError> {
    let status = block_of(rule)?.status;
    crate::deploy::strategy(cx, DISPLAY, &status)
}

/// Whitespace collapsed, normalised, cut at 1024 characters with a trailing
/// `…` (`derive_description`).
pub fn derive_description(description: &str) -> String {
    let collapsed: Vec<&str> = description
        .split(is_python_space)
        .filter(|word| !word.is_empty())
        .collect();
    let text = normalise(&collapsed.join(" "));
    if text.chars().count() <= DESCRIPTION_LIMIT {
        return text;
    }
    let mut cut = cut(&text, DESCRIPTION_LIMIT - 1);
    cut.push('\u{2026}');
    cut
}

/// The block's `severity`, else `response.alert_severity`'s, else Medium
/// (`derive_severity`).
pub fn derive_severity(rule: &Rule, block: &BitdefenderConfig) -> i64 {
    if let Some(severity) = block.severity {
        return severity.level();
    }
    let Some(written) = rule
        .response()
        .and_then(|response| response.get("alert_severity"))
    else {
        return DEFAULT_SEVERITY;
    };
    let text = crate::deploy::text(written);
    alert_severity(&opentide_schema::objects::platform::python_strip(&text).to_lowercase())
        .unwrap_or(DEFAULT_SEVERITY)
}

/// Block, ATT&CK, `opentide`, `opentide:<uuid>` and tenant tags; normalised,
/// cut at 128 characters, at least two long, unique (`derive_tags`).
pub fn derive_tags(
    cx: &Context<'_>,
    rule: &Rule,
    block: &BitdefenderConfig,
    tenant_tags: &[String],
) -> Vec<String> {
    let mut candidates: Vec<String> = block.tags.clone().unwrap_or_default();
    candidates.extend(crate::elastic::rule_techniques(cx, rule));
    candidates.push("opentide".to_owned());
    candidates.push(format!("opentide:{}", rule.uuid));
    candidates.extend(tenant_tags.iter().cloned());
    let mut tags: Vec<String> = Vec::new();
    for candidate in candidates {
        let tag = cut(&normalise(&candidate), TAG_LIMIT);
        if tag.chars().count() >= TAG_MINIMUM && !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    tags
}

fn scope(action: &ProcessAction) -> Json {
    let scope = action.scope();
    let mut settings = Object::new();
    settings.insert("includeParent".into(), Json::Bool(scope.include_parent));
    settings.insert("includeChildren".into(), Json::Bool(scope.include_children));
    Json::Object(settings)
}

/// Every action type the kind allows, in type order, each enabled `true` or
/// `false` (`automatic_actions`).
pub fn automatic_actions(kind: Kind, actions: Option<&BitdefenderActions>) -> Vec<Json> {
    let mut entries = Vec::new();
    for (key, code) in ACTION_TYPES {
        if kind == Kind::Yara && NOT_ON_YARA.contains(&key) {
            continue;
        }
        let settings: Option<Option<Json>> = actions.and_then(|actions| match key {
            "isolate" => actions.isolate.map(|_| None),
            "collect_investigation_package" => actions.collect_investigation_package.map(|_| None),
            "sandbox" => actions.sandbox.map(|_| None),
            "kill_process" => actions
                .kill_process
                .as_ref()
                .map(|action| Some(scope(action))),
            "antimalware_scan" => actions.antimalware_scan.map(|scan| {
                let mut settings = Object::new();
                let kind = if scan == ScanType::Quick { 1 } else { 2 };
                settings.insert("type".into(), Json::Int(kind));
                Some(Json::Object(settings))
            }),
            "quarantine" => actions
                .quarantine
                .as_ref()
                .map(|action| Some(scope(action))),
            "risk_scan" => actions.risk_scan.map(|_| None),
            _ => None,
        });
        let mut entry = Object::new();
        entry.insert("type".into(), Json::Int(code));
        entry.insert("enabled".into(), Json::Bool(settings.is_some()));
        if let Some(Some(settings)) = settings {
            entry.insert("settings".into(), settings);
        }
        entries.push(Json::Object(entry));
    }
    entries
}

/// The signature with `\n` line endings and one trailing newline
/// (`yara_query`).
pub fn yara_query(signature: &str) -> String {
    let text = signature.replace("\r\n", "\n").replace('\r', "\n");
    if text.ends_with('\n') {
        text
    } else {
        text + "\n"
    }
}

fn criterion_value(value: &serde_json::Value) -> Json {
    match value {
        serde_json::Value::String(text) => Json::Str(text.clone()),
        serde_json::Value::Number(number) => number.as_i64().map_or(Json::Null, Json::Int),
        serde_json::Value::Array(items) => Json::Array(items.iter().map(criterion_value).collect()),
        _ => Json::Null,
    }
}

/// `settings` by kind (bitdefender-1.0, Deploy; `derive_settings`).
pub fn derive_settings(
    rule: &Rule,
    block: &BitdefenderConfig,
    strategy: StatusStrategy,
    automatic: bool,
) -> Result<Object, CompileError> {
    let disabled = strategy == StatusStrategy::Disablement;
    let severity = derive_severity(rule, block);
    let mut settings = Object::new();
    if let Some(yara) = &block.yara {
        let status = i64::from(!disabled && yara.on_access);
        settings.insert("status".into(), Json::Int(status));
        settings.insert("severity".into(), Json::Int(severity));
        settings.insert("yaraQuery".into(), yara_query(&yara.signature).into());
    } else {
        let Some(detection) = &block.detection else {
            return Err(CompileError::failed(
                DISPLAY,
                &format!("Rule {} has neither detection nor yara", rule.uuid),
            ));
        };
        settings.insert("status".into(), Json::Int(i64::from(!disabled)));
        settings.insert("severity".into(), Json::Int(severity));
        settings.insert("target".into(), detection.target.clone().into());
        let mut criteria = Vec::with_capacity(detection.criteria.len());
        for criterion in &detection.criteria {
            let Some((relation, value)) = criterion.relation() else {
                return Err(CompileError::failed(
                    DISPLAY,
                    &format!("criterion on {} has no relation", criterion.field),
                ));
            };
            let mut entry = Object::new();
            entry.insert("field".into(), criterion.field.clone().into());
            entry.insert("relation".into(), relation.into());
            entry.insert("value".into(), criterion_value(&value));
            criteria.push(Json::Object(entry));
        }
        settings.insert("criteriaList".into(), Json::Array(criteria));
        if let Some(alert) = detection.alert.as_deref().filter(|alert| !alert.is_empty()) {
            let mut filter = Object::new();
            filter.insert("field".into(), "detection".into());
            filter.insert("value".into(), alert.into());
            settings.insert("filters".into(), Json::Array(vec![Json::Object(filter)]));
        }
    }
    if automatic {
        settings.insert(
            "automaticActions".into(),
            Json::Array(automatic_actions(block.kind(), block.actions.as_ref())),
        );
    }
    Ok(settings)
}

fn aliases(value: Option<&Json>) -> Vec<String> {
    match value {
        Some(Json::Array(items)) => items.iter().map(crate::deploy::text).collect(),
        _ => Vec::new(),
    }
}

/// `targets` aliases to GravityZone ids (`resolve_targets`):
/// `bitdefender_target_unknown` for an unknown one. `None` only when there
/// are no targets at all. Targets that hold no alias (`{}`, an empty or null
/// list) are refused: they must never resolve to the whole company
/// (`bitdefender_targets_shape`).
pub fn resolve_targets(
    targets: Option<&Json>,
    endpoint_tags: Option<&Json>,
    companies: Option<&Json>,
) -> Result<Option<Json>, CompileError> {
    let Some(targets) = targets else {
        return Ok(None);
    };
    let shaped = serde_json::to_value(targets).is_ok_and(|value| {
        value.as_object().is_some_and(|map| !map.is_empty()) && targets_shape_ok_json(&value)
    });
    if !shaped {
        return Err(target_error(
            TARGETS_SHAPE,
            "targets sets exactly one of endpoint_tags and companies, a non-empty list of \
             aliases; leave targets out for the whole company",
            None,
        ));
    }
    let tags = aliases(targets.get("endpoint_tags"));
    if !tags.is_empty() {
        let known = |alias: &str| endpoint_tags.and_then(|table| table.get(alias));
        let missing: Vec<&str> = tags
            .iter()
            .map(String::as_str)
            .filter(|alias| known(alias).is_none())
            .collect();
        if !missing.is_empty() {
            return Err(target_error(
                TARGET_UNKNOWN,
                &format!(
                    "endpoint tag alias(es) {} are not in the tenant's endpoint_tags table",
                    missing.join(", ")
                ),
                None,
            ));
        }
        let resolved = tags
            .iter()
            .filter_map(|alias| known(alias))
            .map(|entry| {
                let mut tag = Object::new();
                for (from, to) in [("tag_id", "tagId"), ("company_id", "companyId")] {
                    tag.insert(to.into(), entry.get(from).cloned().unwrap_or(Json::Null));
                }
                Json::Object(tag)
            })
            .collect();
        let mut out = Object::new();
        out.insert("endpointTags".into(), Json::Array(resolved));
        return Ok(Some(Json::Object(out)));
    }
    let names = aliases(targets.get("companies"));
    if !names.is_empty() {
        let known = |alias: &str| companies.and_then(|table| table.get(alias));
        let missing: Vec<&str> = names
            .iter()
            .map(String::as_str)
            .filter(|alias| known(alias).is_none())
            .collect();
        if !missing.is_empty() {
            return Err(target_error(
                TARGET_UNKNOWN,
                &format!(
                    "company alias(es) {} are not in the tenant's companies table",
                    missing.join(", ")
                ),
                None,
            ));
        }
        let ids = names
            .iter()
            .filter_map(|alias| known(alias))
            .cloned()
            .collect();
        let mut out = Object::new();
        out.insert("companiesIds".into(), Json::Array(ids));
        return Ok(Some(Json::Object(out)));
    }
    Ok(None)
}

/// The block's `targets` as authored, without its unset lists.
fn block_targets(block: &BitdefenderConfig) -> Option<Json> {
    let targets = block.targets.as_ref()?;
    let mut out = Object::new();
    if let Some(tags) = &targets.endpoint_tags {
        out.insert("endpoint_tags".into(), tags.clone().into());
    }
    if let Some(companies) = &targets.companies {
        out.insert("companies".into(), companies.clone().into());
    }
    Some(Json::Object(out))
}

/// What `rule` deploys under `strategy` on `tenant` (`compile_rule`). Without
/// a tenant (an offline preview) there are no tenant tags, default targets
/// or `companyId`, and `targets` is left out: its aliases resolve only
/// against a tenant ([`unresolved_targets`] names them). With one, a target
/// error names the tenant (`compile_deployment`).
pub fn compile_rule(
    cx: &Context<'_>,
    rule: &Rule,
    strategy: StatusStrategy,
    tenant: Option<&Json>,
) -> Result<GravityZoneRule, CompileError> {
    let block = block_of(rule)?;
    let automatic = tenant
        .and_then(|tenant| setup(tenant, "automatic_actions"))
        .is_none_or(Json::truthy);
    let mut targets = None;
    let mut tenant_tags = Vec::new();
    let mut company_id = None;
    if let Some(tenant) = tenant {
        let authored = block_targets(&block).filter(Json::truthy);
        let chosen = authored.as_ref().or_else(|| setup(tenant, "targets"));
        targets = resolve_targets(
            chosen,
            setup(tenant, "endpoint_tags"),
            setup(tenant, "companies"),
        )
        .map_err(|error| {
            target_error(
                error.code,
                &error.reason,
                Some(crate::deploy::tenant_name(tenant)),
            )
        })?;
        tenant_tags = aliases(setup(tenant, "tags"));
        company_id = setup(tenant, "company_id").map(crate::deploy::text);
    }
    Ok(GravityZoneRule {
        uuid: rule.uuid.clone(),
        kind: block.kind(),
        name: gravityzone_name(&rule.name, Some(&block.name)),
        description: derive_description(rule.description()),
        tags: derive_tags(cx, rule, &block, &tenant_tags),
        settings: derive_settings(rule, &block, strategy, automatic)?,
        targets,
        company_id,
    })
}

/// The block's `targets` aliases, which only a tenant resolves
/// (`unresolved_targets`).
pub fn unresolved_targets(rule: &Rule) -> Result<Option<Json>, CompileError> {
    Ok(block_targets(&block_of(rule)?))
}

/// `createCustomRule` params, with `returnRuleId: true` (`create_params`).
pub fn create_params(compiled: &GravityZoneRule) -> Json {
    let mut params = Object::new();
    params.insert("type".into(), Json::Int(RULE_TYPE));
    params.insert("subtype".into(), Json::Int(compiled.kind.subtype()));
    params.insert("name".into(), compiled.name.clone().into());
    params.insert("description".into(), compiled.description.clone().into());
    params.insert("tags".into(), compiled.tags.clone().into());
    params.insert("settings".into(), Json::Object(compiled.settings.clone()));
    if let Some(targets) = compiled.targets.as_ref().filter(|targets| targets.truthy()) {
        params.insert("targets".into(), targets.clone());
    }
    if let Some(company) = compiled.company_id.as_deref().filter(|id| !id.is_empty()) {
        params.insert("companyId".into(), company.into());
    }
    params.insert("returnRuleId".into(), Json::Bool(true));
    Json::Object(params)
}

/// `settings` with `filters: []` on a Basic rule without `alert`, where a
/// create puts `filters`: before the actions (`_update_settings`).
fn update_settings(compiled: &GravityZoneRule) -> Object {
    if compiled.kind != Kind::Detection || compiled.settings.contains_key("filters") {
        return compiled.settings.clone();
    }
    let mut settings = Object::new();
    for (key, value) in &compiled.settings {
        if key == "automaticActions" {
            settings.insert("filters".into(), Json::Array(Vec::new()));
        }
        settings.insert(key.clone(), value.clone());
    }
    settings
        .entry("filters".to_owned())
        .or_insert_with(|| Json::Array(Vec::new()));
    settings
}

/// `updateCustomRule` params: `ruleId` and the whole payload
/// (`update_params`). Nothing is left to the stored rule.
pub fn update_params(compiled: &GravityZoneRule, rule_id: &str) -> Json {
    let mut params = Object::new();
    params.insert("ruleId".into(), rule_id.into());
    params.insert("type".into(), Json::Int(RULE_TYPE));
    params.insert("name".into(), compiled.name.clone().into());
    params.insert("description".into(), compiled.description.clone().into());
    params.insert("tags".into(), compiled.tags.clone().into());
    params.insert("settings".into(), Json::Object(update_settings(compiled)));
    params.insert(
        "targets".into(),
        compiled
            .targets
            .clone()
            .filter(Json::truthy)
            .unwrap_or_else(|| Json::Object(Object::new())),
    );
    Json::Object(params)
}

/// `deleteCustomRule` params (`delete_params`).
pub fn delete_params(rule_id: &str) -> Json {
    let mut params = Object::new();
    params.insert("ruleId".into(), rule_id.into());
    params.insert("type".into(), Json::Int(RULE_TYPE));
    Json::Object(params)
}

/// The JSON-RPC 2.0 body without its per-request `id` (`request_body`).
pub fn request_body(method: &str, params: Json) -> Json {
    let mut body = Object::new();
    body.insert("jsonrpc".into(), "2.0".into());
    body.insert("method".into(), method.into());
    body.insert("params".into(), params);
    Json::Object(body)
}

/// The request a deploy sends for `rule` on `tenant` under `action`, as a
/// body without its `id`: what a dry run shows and the connector sends.
pub fn request(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: &Json,
    action: &Action,
) -> Result<Json, CompileError> {
    if let Action::Delete(rule_id) = action {
        return Ok(request_body(DELETE, delete_params(rule_id)));
    }
    let compiled = compile_rule(cx, rule, strategy(cx, rule)?, Some(tenant))?;
    Ok(match action {
        Action::Update(rule_id) => request_body(UPDATE, update_params(&compiled, rule_id)),
        _ => request_body(CREATE, create_params(&compiled)),
    })
}
