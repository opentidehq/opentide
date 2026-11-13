//! A dry run's payload entries (`deployment/preview.py`): what each rule
//! would send, or why it would fail.

use opentide_schema::objects::platform::{
    CarbonBlackConfig, CrowdstrikeConfig, DefenderConfig, ElasticConfig, GoogleSecopsConfig,
    HarfangLabConfig, SentinelConfig, SentinelOneConfig, SplunkConfig, SysdigConfig,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::{
    Context, carbon_black, crowdstrike, defender, deploy, elastic, google_secops, harfanglab,
    sentinel, sentinel_one, splunk, sysdig,
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
        "google_secops" => Some(google_secops::compile_offline(cx, rule)),
        _ => None,
    }
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
        // The text is the same on every tenant: the `rules.create` body.
        "google_secops" => Some(google_secops::compile_offline(cx, rule)),
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
        "google_secops" => model_dump::<GoogleSecopsConfig>(block),
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

/// The preview of `rule` on `platform` (`preview_rule_deployment`), the
/// entry the dry run's `payloads` lists. Sentinel and Sysdig report a rule
/// they cannot compile as a failure; Elastic falls back to the block's dump,
/// and every other platform shows it ([`config_dump`]).
pub fn preview(cx: &Context<'_>, platform: &str, rule: &Rule) -> Json {
    match platform {
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
