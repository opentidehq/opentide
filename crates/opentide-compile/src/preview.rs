//! A dry run's payload entries (`deployment/preview.py`): what each rule
//! would send, or why it would fail.

use opentide_schema::objects::platform::{
    BitdefenderConfig, CarbonBlackConfig, CrowdstrikeConfig, DefenderConfig, ElasticConfig,
    GoogleSecopsConfig, GraylogConfig, HarfangLabConfig, SentinelConfig, SentinelOneConfig,
    SplunkConfig, SysdigConfig,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::{
    Context, bitdefender, carbon_black, crowdstrike, defender, deploy, elastic, google_secops,
    graylog, harfanglab, sentinel, sentinel_one, splunk, sysdig,
};

/// The tenant a preview compiles for: exclusions scoped to a tenant name are
/// left out, so the payload is the one any tenant without a tenant-specific
/// exclusion receives.
pub const PREVIEW_TENANT: &str = "corpus-tenant";

/// The platforms whose request body opentide builds from the rule alone,
/// with no tenant (`OFFLINE_COMPILERS`), that this crate compiles: those
/// [`compile_offline`] compiles.
pub fn offline() -> Vec<&'static str> {
    use opentide_schema::platforms::{Order, ids_where};
    ids_where(Order::Container, |platform| platform.compiles_offline)
}

/// The request body a deploy would send for `rule` on `platform` with no
/// tenant (`compile_offline`). `None` for a platform this crate does not
/// compile offline.
pub fn compile_offline(
    cx: &Context<'_>,
    platform: &str,
    rule: &Rule,
) -> Option<Result<Json, CompileError>> {
    match platform {
        "sentinel" => Some(sentinel::compile(cx, rule, PREVIEW_TENANT)),
        "elastic" => Some(elastic::compile(cx, rule, &elastic::Setup::none())),
        "sysdig" => Some(sysdig::compile_body(cx, rule, None)),
        "bitdefender" => Some(bitdefender_request(cx, rule, None)),
        "google_secops" => Some(google_secops::compile_offline(cx, rule)),
        "graylog" => Some(graylog_request(cx, rule, None)),
        _ => None,
    }
}

/// The `POST /api/events/definitions` request a deploy would send for
/// `rule` on `tenant` (none: aliases left out), built for
/// [`graylog::PREVIEW_VERSION`]: a preview asks no server.
fn graylog_request(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: Option<&Json>,
) -> Result<Json, CompileError> {
    let setup = tenant.and_then(graylog::tenant_setup);
    let name = tenant.map(deploy::tenant_name);
    graylog::compile_definition(cx, rule, graylog::PREVIEW_VERSION, setup, name)
        .map(|compiled| graylog::create_request(&compiled))
}

/// The `createCustomRule` request a deploy sends for `rule` on `tenant`;
/// with none, without the tenant's targets, tags and `companyId`.
fn bitdefender_request(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: Option<&Json>,
) -> Result<Json, CompileError> {
    let strategy = bitdefender::strategy(cx, rule)?;
    let compiled = bitdefender::compile_rule(cx, rule, strategy, tenant)?;
    Ok(bitdefender::request_body(
        bitdefender::CREATE,
        bitdefender::create_params(&compiled),
    ))
}

/// The platforms whose deployer builds the body from the tenant (and, for
/// Defender, SentinelOne and CrowdStrike, the deployment state): those
/// [`compile_tenant`] builds writes for.
pub fn deployers() -> Vec<&'static str> {
    use opentide_schema::platforms::{Order, ids_where};
    ids_where(Order::Container, |platform| {
        platform.deploys && !platform.compiles_offline
    })
}

/// What a deployer's body depends on besides the rule and the tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inputs {
    /// The id the deployment state records for the rule on the tenant.
    pub known: Option<String>,
    /// Splunk's schedule minute and hour.
    pub clock: splunk::Clock,
    /// Carbon Black's report timestamp (UNIX seconds).
    pub timestamp: i64,
}

/// The Splunk clock the oracle's probe pins (`xtask/src/payloads/probe.py`):
/// a random minute and hour of 7, the time 03:04 UTC.
pub const PROBE_CLOCK: splunk::Clock = splunk::Clock {
    random: (7, 7),
    now: (4, 3),
};

/// The Carbon Black report timestamp the oracle's probe pins.
pub const PROBE_TIMESTAMP: i64 = 1_767_225_600;

/// What a deploy sends for `rule` on `platform` to the tenant named
/// `tenant`: the body (Sentinel, Elastic, Sysdig) or the writes, in order
/// (the deployers). `None` for a platform this crate does not know.
pub fn compile_tenant(
    cx: &Context<'_>,
    platform: &str,
    rule: &Rule,
    tenant: &str,
    inputs: &Inputs,
) -> Option<Result<Json, CompileError>> {
    let known = deploy::tenant(cx, platform, tenant);
    let empty = Json::Object(Object::new());
    let config = known.unwrap_or(&empty);
    let writes = |result: Result<Vec<deploy::Write>, CompileError>| {
        Some(result.map(|writes| deploy::writes_json(&writes)))
    };
    let id = inputs.known.as_deref();
    match platform {
        "sentinel" => Some(sentinel::compile(cx, rule, tenant)),
        "sysdig" => Some(sysdig::compile_body(cx, rule, known)),
        "bitdefender" => Some(bitdefender_tenant(cx, rule, config, id)),
        // The text is the same on every tenant: the `rules.create` body.
        "google_secops" => Some(google_secops::compile_offline(cx, rule)),
        "graylog" => Some(graylog_request(cx, rule, known)),
        "elastic" => {
            let setup = known.map_or_else(elastic::Setup::none, elastic::Setup::from_tenant);
            Some(elastic::compile(cx, rule, &setup))
        }
        "defender_for_endpoint" => writes(defender::compile(cx, rule, tenant, id)),
        "sentinel_one" => writes(sentinel_one::compile(cx, rule, config, id)),
        "crowdstrike" => writes(crowdstrike::compile(cx, rule, config, id)),
        "harfanglab" => writes(harfanglab::compile(cx, rule, config)),
        "splunk" => writes(splunk::compile(cx, rule, config, inputs.clock)),
        "carbon_black_cloud" => writes(carbon_black::compile(cx, rule, config, inputs.timestamp)),
        _ => None,
    }
}

/// The request a deploy sends for `rule` on the GravityZone `tenant`, under
/// the action its status and the recorded id `known` make (`[]` when there
/// is nothing to do).
fn bitdefender_tenant(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: &Json,
    known: Option<&str>,
) -> Result<Json, CompileError> {
    let status = bitdefender::block_of(rule)?.status;
    match deploy::action(cx, bitdefender::DISPLAY, &status, known)? {
        Some(action) => bitdefender::request(cx, rule, tenant, &action),
        None => Ok(Json::Array(Vec::new())),
    }
}

/// The block read by its model and serialised, fields in declaration order.
fn model_dump<T: DeserializeOwned + Serialize>(block: &Json) -> Option<Json> {
    let model: T = serde_json::from_str(&block.to_compact()).ok()?;
    Json::from_serialize(&model).ok()
}

/// The block of `platform` as the dry run shows it when it builds no body
/// (`_config_preview`, Pydantic's `model_dump`): opentide-schema's model,
/// serialised by serde. An unset optional field is left out where the
/// oracle writes it `null`, and a mapping keeps its model's order
/// (`tests/golden/payloads/APPROVED.toml`). A block the model refuses is
/// shown as written.
pub fn config_dump(platform: &str, block: &Json) -> Json {
    let dumped = match platform {
        "sentinel" => model_dump::<SentinelConfig>(block),
        "defender_for_endpoint" => model_dump::<DefenderConfig>(block),
        "splunk" => model_dump::<SplunkConfig>(block),
        "sentinel_one" => model_dump::<SentinelOneConfig>(block),
        "crowdstrike" => model_dump::<CrowdstrikeConfig>(block),
        "harfanglab" => model_dump::<HarfangLabConfig>(block),
        "carbon_black_cloud" => model_dump::<CarbonBlackConfig>(block),
        "elastic" => model_dump::<ElasticConfig>(block),
        "sysdig" => model_dump::<SysdigConfig>(block),
        "bitdefender" => model_dump::<BitdefenderConfig>(block),
        "google_secops" => model_dump::<GoogleSecopsConfig>(block),
        "graylog" => model_dump::<GraylogConfig>(block),
        _ => None,
    };
    dumped.unwrap_or_else(|| block.clone())
}

/// The entry of a rule shown as its block's dump (`_config_preview`).
fn dump_entry(platform: &str, rule: &Rule) -> Json {
    let mut entry = Object::new();
    entry.insert("uuid".into(), rule.uuid.clone().into());
    entry.insert("name".into(), rule.name.clone().into());
    entry.insert(
        "api_request".into(),
        rule.block(platform).map_or_else(
            || Json::Object(Object::new()),
            |block| config_dump(platform, block),
        ),
    );
    Json::Object(entry)
}

/// The entry of a rule that compiled.
fn compiled(rule: &Rule, body: Json) -> Json {
    let mut entry = Object::new();
    entry.insert("uuid".into(), rule.uuid.clone().into());
    entry.insert("name".into(), rule.name.clone().into());
    entry.insert("api_request".into(), body);
    Json::Object(entry)
}

/// The entry of a rule that would fail to deploy (`_compile_failure`).
pub fn failure(rule: &Rule, error: &CompileError) -> Json {
    let mut entry = Object::new();
    entry.insert("uuid".into(), rule.uuid.clone().into());
    entry.insert("name".into(), rule.name.clone().into());
    entry.insert("status".into(), "failed".into());
    entry.insert("code".into(), error.code.into());
    entry.insert("error".into(), error.reason.clone().into());
    entry.insert(
        "help".into(),
        error.hint.clone().map_or(Json::Null, Json::Str),
    );
    entry.insert(
        "file".into(),
        rule.file.clone().map_or(Json::Null, Json::Str),
    );
    entry.insert("api_request".into(), Json::Null);
    Json::Object(entry)
}

/// The preview of `rule` on `platform` for a run that sends it to the
/// tenants named `tenants` (`preview_rule_deployment`): a platform whose
/// request depends on the tenant (Bitdefender) compiles it for each, and
/// shows the first; every other platform is [`preview`]'s.
pub fn preview_on(cx: &Context<'_>, platform: &str, rule: &Rule, tenants: &[String]) -> Json {
    match platform {
        "bitdefender" => bitdefender_preview(cx, rule, tenants),
        "graylog" => graylog_preview(cx, rule, tenants),
        _ => preview(cx, platform, rule),
    }
}

/// The `createCustomRule` request the deploy would send
/// (`_bitdefender_compile_preview`): compiled for each tenant the run sends
/// the rule to, as a deploy would, so a tenant that cannot resolve the
/// block's targets fails the dry run, naming that tenant. The request shown
/// is the first tenant's. With no tenant, it leaves targets, tenant tags and
/// `companyId` out, and `unresolved` names the block's target aliases, never
/// presented as GravityZone ids.
fn bitdefender_preview(cx: &Context<'_>, rule: &Rule, tenants: &[String]) -> Json {
    let configured: Vec<&Json> = tenants
        .iter()
        .filter_map(|name| deploy::tenant(cx, bitdefender::PLATFORM, name))
        .collect();
    let mut first = None;
    let attempts: Vec<Option<&Json>> = if configured.is_empty() {
        vec![None]
    } else {
        configured.iter().copied().map(Some).collect()
    };
    for tenant in attempts {
        match bitdefender_request(cx, rule, tenant) {
            Ok(body) => {
                first.get_or_insert(body);
            }
            Err(error) => return failure(rule, &error),
        }
    }
    let mut entry = Object::new();
    entry.insert("uuid".into(), rule.uuid.clone().into());
    entry.insert("name".into(), rule.name.clone().into());
    entry.insert("api_request".into(), first.unwrap_or(Json::Null));
    if let Some(tenant) = configured.first() {
        entry.insert("tenant".into(), deploy::tenant_name(tenant).into());
    } else {
        let mut unresolved = Object::new();
        unresolved.insert(
            "reason".into(),
            "this run deploys the rule to no bitdefender tenant: targets, tenant tags and \
             companyId are resolved against a tenant at deploy"
                .into(),
        );
        unresolved.insert(
            "targets".into(),
            bitdefender::unresolved_targets(rule)
                .ok()
                .flatten()
                .unwrap_or(Json::Null),
        );
        entry.insert("unresolved".into(), Json::Object(unresolved));
    }
    Json::Object(entry)
}

/// The preview of `rule` on `platform` (`preview_rule_deployment`), the
/// entry the dry run's `payloads` lists. Sentinel, Sysdig and Graylog report
/// a rule they cannot compile as a failure; Elastic falls back to the
/// block's dump, and every other platform shows it ([`config_dump`]).
/// `tenants` are the tenants the run sends the rule to, which Graylog's
/// request depends on.
pub fn preview(cx: &Context<'_>, platform: &str, rule: &Rule) -> Json {
    match platform {
        "graylog" => graylog_preview(cx, rule, &[]),
        // A compile error the oracle reports with the platform's display
        // name: compile_diagnostic(exc) names Sentinel.
        "sentinel" => match sentinel::compile(cx, rule, PREVIEW_TENANT) {
            Ok(body) => compiled(rule, body),
            Err(error) => failure(rule, &error),
        },
        // The oracle names Sentinel in a Sysdig failure (`_compile_failure`
        // calls `compile_diagnostic(exc)` without the platform); this names
        // Sysdig (tests/golden/payloads/APPROVED.toml).
        "sysdig" => match sysdig::compile_body(cx, rule, None) {
            Ok(body) => compiled(rule, body),
            Err(error) => failure(rule, &error),
        },
        // `_google_secops_compile_preview`: the `rules.create` body, or the
        // failure, named for Google SecOps.
        "google_secops" => match google_secops::compile_offline(cx, rule) {
            Ok(body) => compiled(rule, body),
            Err(error) => failure(rule, &error),
        },
        "elastic" => match elastic::compile(cx, rule, &elastic::Setup::none()) {
            Ok(body) => compiled(rule, body),
            Err(_) => dump_entry(platform, rule),
        },
        _ => dump_entry(platform, rule),
    }
}

/// Graylog's preview (`_graylog_compile_preview`): the create request for
/// [`graylog::PREVIEW_VERSION`], compiled for every tenant the run sends the
/// rule to, so one whose tables miss an alias fails the dry run and is
/// named. The request shown is the first tenant's; with no tenant, stream
/// and notification ids are left out and `unresolved` lists the aliases.
fn graylog_preview(cx: &Context<'_>, rule: &Rule, tenants: &[String]) -> Json {
    let found: Vec<&Json> = tenants
        .iter()
        .filter_map(|name| deploy::tenant(cx, graylog::PLATFORM, name))
        .collect();
    let mut compiled = Vec::new();
    let reached: Vec<Option<&Json>> = if found.is_empty() {
        vec![None]
    } else {
        found.iter().copied().map(Some).collect()
    };
    for tenant in reached {
        let setup = tenant.and_then(graylog::tenant_setup);
        let name = tenant.map(deploy::tenant_name);
        match graylog::compile_definition(cx, rule, graylog::PREVIEW_VERSION, setup, name) {
            Ok(definition) => compiled.push(definition),
            Err(error) => return failure(rule, &error),
        }
    }
    let Some(first) = compiled.first() else {
        return dump_entry(graylog::PLATFORM, rule);
    };
    let mut entry = Object::new();
    entry.insert("uuid".into(), rule.uuid.clone().into());
    entry.insert("name".into(), rule.name.clone().into());
    entry.insert("api_request".into(), graylog::create_request(first));
    let version = graylog::PREVIEW_VERSION;
    entry.insert(
        "server_version".into(),
        format!("{}.{}", version.0, version.1).into(),
    );
    if let Some(tenant) = found.first() {
        entry.insert("tenant".into(), deploy::tenant_name(tenant).into());
    } else if !first.unresolved.is_empty() {
        let mut unresolved = Object::new();
        unresolved.insert(
            "reason".into(),
            "this run deploys the rule to no graylog tenant: stream and notification aliases \
             are resolved against a tenant at deploy"
                .into(),
        );
        for (field, aliases) in &first.unresolved {
            unresolved.insert(
                (*field).to_owned(),
                Json::Array(aliases.iter().cloned().map(Json::Str).collect()),
            );
        }
        entry.insert("unresolved".into(), Json::Object(unresolved));
    }
    Json::Object(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_dumps_in_its_models_order_with_its_defaults() {
        let block: Json = serde_json::from_str(
            r#"{"query":"q","status":"STAGING","condition":{"type":"Single Event","single_event":{"query":"q"}},"response":{"network_quarantine":true,"treat_as_threat":false}}"#,
        )
        .unwrap();
        // `query` is not a SentinelOne field: the block is shown as written.
        assert_eq!(config_dump("sentinel_one", &block), block);
        let Json::Object(mut valid) = block else {
            unreachable!()
        };
        valid.shift_remove("query");
        assert_eq!(
            config_dump("sentinel_one", &Json::Object(valid)).to_compact(),
            r#"{"enabled":false,"name":"","status":"STAGING","condition":{"type":"Single Event","single_event":{"query":"q"}},"response":{"treat_as_threat":false,"network_quarantine":true}}"#
        );
    }
}
