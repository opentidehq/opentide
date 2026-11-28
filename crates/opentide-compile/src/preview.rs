//! A dry run's payload entries (`deployment/preview.py`): what each rule
//! would send, or why it would fail.

use opentide_schema::objects::platform::{
    BitdefenderConfig, CarbonBlackConfig, CrowdstrikeConfig, DatadogConfig, ElasticConfig,
    ExabeamConfig, GoogleSecopsConfig, GraylogConfig, HarfangLabConfig, MicrosoftDefenderConfig,
    SentinelConfig, SentinelOneConfig, SplunkConfig, SysdigConfig,
};
use opentide_schema::platforms::{PlatformId, PlatformKey};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::compiler::{
    Bitdefender, Compiler, Datadog, Exabeam, GoogleSecops, Graylog, GraylogTarget, Sentinel, Sysdig,
};
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::{
    Context, bitdefender, carbon_black, crowdstrike, datadog, deploy, elastic, exabeam,
    google_secops, graylog, harfanglab, microsoft_defender, plan, sentinel_one, splunk,
};

/// The tenant a preview compiles for: exclusions scoped to a tenant name are
/// left out, so the payload is the one any tenant without a tenant-specific
/// exclusion receives.
pub const PREVIEW_TENANT: &str = "corpus-tenant";

/// The [`deployers`] as a pattern on [`PlatformId`]: the platforms whose
/// deploy sends writes compiled from the tenant ([`tenant_writes`]). A test
/// holds it to the registry's flags.
macro_rules! deployer {
    () => {
        PlatformId::MicrosoftDefender
            | PlatformId::Splunk
            | PlatformId::SentinelOne
            | PlatformId::Crowdstrike
            | PlatformId::Harfanglab
            | PlatformId::CarbonBlackCloud
    };
}

/// The platforms whose request body opentide builds from the rule alone,
/// with no tenant (`OFFLINE_COMPILERS`), that this crate compiles: those
/// [`compile_offline`] compiles.
pub fn offline() -> Vec<PlatformId> {
    PlatformId::ALL
        .into_iter()
        .filter(|platform| platform.spec().compiles_offline)
        .collect()
}

/// The request body a deploy would send for `rule` on `platform` with no
/// tenant (`compile_offline`). `None` for one of the [`deployers`], whose
/// body needs the tenant.
pub fn compile_offline(
    cx: &Context<'_>,
    platform: PlatformId,
    rule: &Rule,
) -> Option<Result<Json, CompileError>> {
    match platform {
        PlatformId::Sentinel => Some(sentinel_body(cx, rule, PREVIEW_TENANT)),
        PlatformId::Elastic => Some(elastic::compile(cx, rule, &elastic::Setup::none())),
        PlatformId::Sysdig => {
            Some(Sysdig::compile(cx, rule, None).map(|compiled| Sysdig::body(&compiled)))
        }
        PlatformId::Bitdefender => Some(bitdefender_request(cx, rule, None)),
        PlatformId::Exabeam => Some(
            Exabeam::compile(cx, rule, None).map(|compiled| exabeam::create_request(&compiled)),
        ),
        PlatformId::GoogleSecops => Some(google_secops::compile_offline(cx, rule)),
        PlatformId::Graylog => Some(graylog_request(cx, rule, None)),
        PlatformId::Datadog => Some(
            Datadog::compile(cx, rule, None).map(|compiled| datadog::create_request(&compiled)),
        ),
        // Their body needs the tenant: [`compile_tenant`] builds it.
        deployer!() => None,
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
    Graylog::compile(cx, rule, preview_target(tenant))
        .map(|compiled| graylog::create_request(&compiled))
}

/// What a Graylog preview compiles for: [`graylog::PREVIEW_VERSION`], since
/// a preview asks no server, and `tenant` (none: aliases left out).
fn preview_target(tenant: Option<&Json>) -> GraylogTarget<'_> {
    GraylogTarget {
        version: graylog::PREVIEW_VERSION,
        tenant,
    }
}

/// The `alertRules` body a Sentinel deploy sends for `rule` to the tenant
/// named `tenant`.
fn sentinel_body(cx: &Context<'_>, rule: &Rule, tenant: &str) -> Result<Json, CompileError> {
    Sentinel::compile(cx, rule, tenant).map(|compiled| Sentinel::body(&compiled))
}

/// The `createCustomRule` request a deploy sends for `rule` on `tenant`;
/// with none, without the tenant's targets, tags and `companyId`.
fn bitdefender_request(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: Option<&Json>,
) -> Result<Json, CompileError> {
    let compiled = Bitdefender::compile(cx, rule, tenant)?;
    Ok(bitdefender::request_body(
        bitdefender::CREATE,
        Bitdefender::body(&compiled),
    ))
}

/// The platforms whose deployer builds the body from the tenant (and, for
/// Defender, SentinelOne and CrowdStrike, the deployment state): those
/// [`compile_tenant`] builds writes for.
pub fn deployers() -> Vec<PlatformId> {
    PlatformId::ALL
        .into_iter()
        .filter(|platform| {
            let spec = platform.spec();
            spec.deploys && !spec.compiles_offline
        })
        .collect()
}

/// What a deployer's body depends on besides the rule and the tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inputs {
    /// The id the deployment state records for the rule on the tenant.
    pub known: Option<String>,
    /// Splunk's schedule minute and hour; `None` in a dry run, which shows
    /// `<send-time:minute>` and `<send-time:hour>` where a deploy draws or
    /// reads them as it sends.
    pub clock: Option<splunk::Clock>,
    /// Carbon Black's report timestamp (UNIX seconds); `None` in a dry run,
    /// which shows `<send-time:timestamp>`.
    pub timestamp: Option<i64>,
}

impl Inputs {
    /// What a dry run knows of a deploy to one tenant: the id the deployment
    /// state records, and nothing a deploy learns only as it sends.
    pub fn dry_run(known: Option<String>) -> Self {
        Self {
            known,
            clock: None,
            timestamp: None,
        }
    }
}

/// What a deploy sends for `rule` on `platform` to the tenant named
/// `tenant`: the body (Sentinel, Elastic, Sysdig) or the writes, in order
/// (the deployers).
pub fn compile_tenant(
    cx: &Context<'_>,
    platform: PlatformId,
    rule: &Rule,
    tenant: &str,
    inputs: &Inputs,
) -> Result<Json, CompileError> {
    let known = deploy::tenant(cx, &platform.into(), tenant);
    let empty = Json::Object(Object::new());
    let config = known.unwrap_or(&empty);
    let id = inputs.known.as_deref();
    match platform {
        deployer!() => tenant_writes(cx, platform, rule, tenant, config, inputs),
        PlatformId::Sentinel => sentinel_body(cx, rule, tenant),
        PlatformId::Sysdig => {
            Sysdig::compile(cx, rule, known).map(|compiled| Sysdig::body(&compiled))
        }
        PlatformId::Bitdefender => bitdefender_tenant(cx, rule, config, id),
        PlatformId::Exabeam => {
            Exabeam::compile(cx, rule, known).map(|compiled| exabeam::create_request(&compiled))
        }
        // The text is the same on every tenant: the `rules.create` body,
        // with what the deploy reads beside it (the run state).
        PlatformId::GoogleSecops => {
            GoogleSecops::compile(cx, rule, ()).map(|compiled| GoogleSecops::body(&compiled))
        }
        PlatformId::Graylog => graylog_request(cx, rule, known),
        PlatformId::Datadog => {
            Datadog::compile(cx, rule, known).map(|compiled| datadog::create_request(&compiled))
        }
        PlatformId::Elastic => {
            let setup = known.map_or_else(elastic::Setup::none, elastic::Setup::from_tenant);
            elastic::compile(cx, rule, &setup)
        }
    }
}

/// The writes a deploy sends for `rule` on one of the [`deployers`] to the
/// tenant named `tenant`, whose table is `config`, in order:
/// `[{"method", "url", "body"}]`. `[]` when there is nothing to send.
fn tenant_writes(
    cx: &Context<'_>,
    platform: PlatformId,
    rule: &Rule,
    tenant: &str,
    config: &Json,
    inputs: &Inputs,
) -> Result<Json, CompileError> {
    let id = inputs.known.as_deref();
    let writes = match platform {
        PlatformId::MicrosoftDefender => microsoft_defender::compile(cx, rule, tenant),
        PlatformId::SentinelOne => sentinel_one::compile(cx, rule, config, id),
        PlatformId::Crowdstrike => crowdstrike::compile(cx, rule, config, id),
        PlatformId::Harfanglab => harfanglab::compile(cx, rule, config),
        PlatformId::Splunk => splunk::compile(cx, rule, config, inputs.clock),
        PlatformId::CarbonBlackCloud => carbon_black::compile(cx, rule, config, inputs.timestamp),
        // Not a deployer: a request, never writes (callers never send one).
        PlatformId::Sentinel
        | PlatformId::Elastic
        | PlatformId::Sysdig
        | PlatformId::Bitdefender
        | PlatformId::Graylog
        | PlatformId::Exabeam
        | PlatformId::GoogleSecops
        | PlatformId::Datadog => Ok(Vec::new()),
    }?;
    Ok(deploy::writes_json(&writes))
}

/// The `setup` keys of `platform` a deploy's requests carry, which a dry run
/// that reaches no tenant shows as `<tenant:KEY>` (a SentinelOne tenant
/// names its site; one that names its account instead gets `accountIds`).
fn tenant_keys(platform: PlatformId) -> &'static [&'static str] {
    match platform {
        PlatformId::SentinelOne => &["url", "site_id"],
        PlatformId::Crowdstrike => &["api", "customer_id"],
        PlatformId::Harfanglab => &["url", "source_id"],
        PlatformId::Splunk => &["url", "port", "app"],
        PlatformId::CarbonBlackCloud => &["url", "org_key", "watchlist"],
        // Defender's requests carry no `setup` value; the others are not
        // deployers.
        PlatformId::MicrosoftDefender
        | PlatformId::Sentinel
        | PlatformId::Elastic
        | PlatformId::Sysdig
        | PlatformId::Bitdefender
        | PlatformId::Graylog
        | PlatformId::Exabeam
        | PlatformId::GoogleSecops
        | PlatformId::Datadog => &[],
    }
}

/// The tenant a dry run that reaches no tenant of `platform` compiles for:
/// named [`PREVIEW_TENANT`], its `setup` holding each value the requests
/// carry as its placeholder ([`tenant_keys`]) and nothing else.
fn unreached_tenant(platform: PlatformId) -> Json {
    let mut setup = Object::new();
    for key in tenant_keys(platform) {
        setup.insert((*key).to_owned(), deploy::tenant_value(key).into());
    }
    let mut tenant = Object::new();
    tenant.insert("name".into(), PREVIEW_TENANT.into());
    tenant.insert("setup".into(), Json::Object(setup));
    Json::Object(tenant)
}

/// Whether `value` holds the placeholder of `key` anywhere.
fn shows(value: &Json, placeholder: &str) -> bool {
    match value {
        Json::Str(text) => text.contains(placeholder),
        Json::Array(items) => items.iter().any(|item| shows(item, placeholder)),
        Json::Object(members) => members.values().any(|member| shows(member, placeholder)),
        _ => false,
    }
}

/// The preview of `rule` on one of the [`deployers`] (#1712): the writes a
/// deploy sends to the first tenant the run sends it to, in order, each
/// `{"method", "url", "body"}`, compiled for every such tenant as a deploy
/// compiles them, so one that cannot take the rule fails the dry run and is
/// named. `known` gives the id the deployment state records for the rule on
/// a tenant. What a deploy learns only as it sends is a `<send-time:NAME>`
/// placeholder. A `setup` value that names a variable (`$NAME`) is shown as
/// `<tenant:KEY>` and named under `unresolved`: a dry run resolves none
/// (#1719). With no tenant, the writes are compiled for a tenant whose
/// `setup` sets nothing, the values a tenant gives shown as `<tenant:KEY>`
/// and named under `unresolved`.
fn requests_preview(
    cx: &Context<'_>,
    platform: PlatformId,
    rule: &Rule,
    tenants: &[String],
    known: &dyn Fn(&str) -> Option<String>,
) -> Json {
    let reached: Vec<(&str, &Json)> = tenants
        .iter()
        .filter_map(|name| {
            deploy::tenant(cx, &platform.into(), name).map(|table| (name.as_str(), table))
        })
        .collect();
    let mut entry = Object::new();
    entry.insert("uuid".into(), rule.uuid.clone().into());
    entry.insert("name".into(), rule.name.clone().into());
    if reached.is_empty() {
        let tenant = unreached_tenant(platform);
        let writes = match tenant_writes(
            cx,
            platform,
            rule,
            PREVIEW_TENANT,
            &tenant,
            &Inputs::dry_run(None),
        ) {
            Ok(writes) => writes,
            Err(error) => return failure(rule, &error),
        };
        let shown = shown_keys(&writes, tenant_keys(platform).iter().copied());
        entry.insert("api_request".into(), writes);
        let mut unresolved = Object::new();
        unresolved.insert(
            "reason".into(),
            format!(
                "this run deploys the rule to no {platform} tenant: the requests are compiled \
                 for a tenant whose setup sets nothing, with no exclusion or modifier scoped to \
                 a tenant, and a value a tenant's setup gives is shown as <tenant:KEY>"
            )
            .into(),
        );
        if !shown.is_empty() {
            unresolved.insert("setup".into(), Json::Array(shown));
        }
        entry.insert("unresolved".into(), Json::Object(unresolved));
        return Json::Object(entry);
    }
    let mut first = None;
    for (name, table) in reached {
        let inputs = Inputs::dry_run(known(name));
        let (shown, variables) = with_placeholders(table);
        let compiled = tenant_writes(cx, platform, rule, name, &shown, &inputs).or_else(|error| {
            // A setting the deploy reads as it is in the table (Splunk's
            // `enterprise_security`) refuses a variable: the deploy's own
            // error says so.
            if variables.is_empty() {
                Err(error)
            } else {
                tenant_writes(cx, platform, rule, name, table, &inputs).and(Err(error))
            }
        });
        match compiled {
            Ok(writes) => {
                first.get_or_insert((name, writes, variables));
            }
            Err(mut error) => {
                error.reason = format!("{} (tenant '{name}')", error.reason);
                return failure(rule, &error);
            }
        }
    }
    let Some((name, writes, variables)) = first else {
        return dump_entry(platform.as_str(), rule);
    };
    let shown = shown_keys(&writes, variables.iter().map(String::as_str));
    entry.insert("api_request".into(), writes);
    entry.insert("tenant".into(), name.into());
    if !shown.is_empty() {
        let mut unresolved = Object::new();
        unresolved.insert(
            "reason".into(),
            format!(
                "the {platform} tenant '{name}' names variables in its setup, which a dry run \
                 does not resolve: each value is shown as <tenant:KEY>"
            )
            .into(),
        );
        unresolved.insert("setup".into(), Json::Array(shown));
        entry.insert("unresolved".into(), Json::Object(unresolved));
    }
    Json::Object(entry)
}

/// `table`, a tenant's, as a dry run compiles for it, and the `setup` keys
/// it changed: each `setup` string that names a variable (`$NAME`,
/// `${NAME}`) is the placeholder `<tenant:KEY>`. A dry run resolves no
/// variable, set or not: it needs no credential, and prints no secret.
fn with_placeholders(table: &Json) -> (Json, Vec<String>) {
    let mut shown = table.clone();
    let mut keys = Vec::new();
    if let Some(setup) = shown.get_mut("setup").and_then(Json::as_object_mut) {
        for (key, value) in setup.iter_mut() {
            // A placeholder's NAME is lowercase letters, digits and `_`
            // (docs/cli/json-output.md), as every setup key is.
            let named = !key.is_empty()
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
            if named && value.as_str().and_then(plan::env_reference).is_some() {
                *value = deploy::tenant_value(key).into();
                keys.push(key.clone());
            }
        }
    }
    (shown, keys)
}

/// The `keys` whose `<tenant:KEY>` placeholder `writes` show, in order.
fn shown_keys<'k>(writes: &Json, keys: impl Iterator<Item = &'k str>) -> Vec<Json> {
    keys.filter(|key| shows(writes, &deploy::tenant_value(key)))
        .map(|key| Json::Str(key.to_owned()))
        .collect()
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

/// The block of `platform` read by its model (`_config_preview`, Pydantic's
/// `model_dump`): opentide-schema's model, serialised by serde. An unset
/// optional field is left out where the oracle writes it `null`, and a
/// mapping keeps its model's order (`tests/golden/payloads/APPROVED.toml`).
/// A block the model refuses is as written. Elastic's checks read it whole.
pub fn config_dump(platform: PlatformId, block: &Json) -> Json {
    model_config_dump(platform, block).unwrap_or_else(|| block.clone())
}

/// The block of `platform` as the dry run shows it when it builds no body
/// (an Elastic rule that does not compile, a platform plugin's):
/// [`config_dump`] without `enabled` and `name` when the block does not
/// write them. Their model defaults (`enabled: false`, `name: ""`) are not
/// what the block says, and no deployer reads them (#1662, D12); every other
/// default stays, since a deploy sends it.
pub fn block_preview(platform: &str, block: &Json) -> Json {
    // A plugin's platform: no model here, the block as written.
    let Some(platform) = PlatformId::parse(platform) else {
        return block.clone();
    };
    let Some(Json::Object(mut dumped)) = model_config_dump(platform, block) else {
        return config_dump(platform, block);
    };
    for key in ["enabled", "name"] {
        if block.get(key).is_none() {
            dumped.shift_remove(key);
        }
    }
    Json::Object(dumped)
}

/// The block read by `platform`'s model, or `None` when the model refuses
/// it or there is none.
fn model_config_dump(platform: PlatformId, block: &Json) -> Option<Json> {
    match platform {
        PlatformId::Sentinel => model_dump::<SentinelConfig>(block),
        PlatformId::MicrosoftDefender => model_dump::<MicrosoftDefenderConfig>(block),
        PlatformId::Splunk => model_dump::<SplunkConfig>(block),
        PlatformId::SentinelOne => model_dump::<SentinelOneConfig>(block),
        PlatformId::Crowdstrike => model_dump::<CrowdstrikeConfig>(block),
        PlatformId::Harfanglab => model_dump::<HarfangLabConfig>(block),
        PlatformId::CarbonBlackCloud => model_dump::<CarbonBlackConfig>(block),
        PlatformId::Elastic => model_dump::<ElasticConfig>(block),
        PlatformId::Sysdig => model_dump::<SysdigConfig>(block),
        PlatformId::Bitdefender => model_dump::<BitdefenderConfig>(block),
        PlatformId::Exabeam => model_dump::<ExabeamConfig>(block),
        PlatformId::GoogleSecops => model_dump::<GoogleSecopsConfig>(block),
        PlatformId::Graylog => model_dump::<GraylogConfig>(block),
        PlatformId::Datadog => model_dump::<DatadogConfig>(block),
    }
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
            |block| block_preview(platform, block),
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
/// request depends on the tenant (Sentinel, Bitdefender, Graylog, Exabeam)
/// compiles it for each, and shows the first; Elastic and Sysdig compile it
/// for the first; every other platform is [`preview`]'s.
pub fn preview_on(
    cx: &Context<'_>,
    platform: &PlatformKey,
    rule: &Rule,
    tenants: &[String],
) -> Json {
    preview_planned(cx, platform, rule, tenants, &|_| None)
}

/// [`preview_on`], where `known` gives the id the deployment state records
/// for the rule on a tenant: the platforms that keep one (Defender for
/// Endpoint, SentinelOne, CrowdStrike) update or delete the rule it names.
pub fn preview_planned(
    cx: &Context<'_>,
    platform: &PlatformKey,
    rule: &Rule,
    tenants: &[String],
    known: &dyn Fn(&str) -> Option<String>,
) -> Json {
    let Some(platform_id) = platform.builtin() else {
        return preview(cx, platform, rule);
    };
    match platform_id {
        PlatformId::Bitdefender => bitdefender_preview(cx, rule, tenants),
        PlatformId::Graylog => graylog_preview(cx, rule, tenants),
        PlatformId::Exabeam => exabeam_preview(cx, rule, tenants),
        PlatformId::Datadog => datadog_preview(cx, rule, tenants),
        PlatformId::Elastic => elastic_preview(cx, rule, tenants),
        deployer!() => requests_preview(cx, platform_id, rule, tenants, known),
        PlatformId::Sentinel => sentinel_preview(cx, rule, tenants),
        PlatformId::Sysdig => sysdig_preview(cx, rule, tenants),
        // The same request on every tenant.
        PlatformId::GoogleSecops => preview(cx, platform, rule),
    }
}

/// The `alertRules` body a Sentinel deploy would send (#2081): compiled, as
/// the deploy compiles it ([`Sentinel`]), for each tenant the run sends the
/// rule to, so a tenant whose exclusions break the rule fails the dry run.
/// The body shown is the first tenant's, with the exclusions scoped to it,
/// and the entry names that `tenant`. With no tenant, it is compiled for
/// [`PREVIEW_TENANT`]: no exclusion scoped to a tenant applies.
fn sentinel_preview(cx: &Context<'_>, rule: &Rule, tenants: &[String]) -> Json {
    let reached: Vec<&str> = tenants
        .iter()
        .map(String::as_str)
        .filter(|name| deploy::tenant(cx, &PlatformId::Sentinel.into(), name).is_some())
        .collect();
    let Some((first, rest)) = reached.split_first() else {
        return sentinel_entry(cx, rule, PREVIEW_TENANT, None);
    };
    let entry = sentinel_entry(cx, rule, first, Some(first));
    if entry.get("status").is_some() {
        return entry;
    }
    for name in rest {
        if let Err(error) = Sentinel::compile(cx, rule, name) {
            return failure(rule, &error);
        }
    }
    entry
}

/// The entry of `rule` compiled for the Sentinel tenant named `tenant`, with
/// the warnings it earned, naming `shown` as its `tenant`; or its failure.
fn sentinel_entry(cx: &Context<'_>, rule: &Rule, tenant: &str, shown: Option<&str>) -> Json {
    match Sentinel::compile(cx, rule, tenant) {
        Ok(sent) => {
            let (body, warnings) = (Sentinel::body(&sent), sent.1);
            let mut entry = compiled(rule, body);
            if let Json::Object(fields) = &mut entry {
                if let Some(name) = shown {
                    fields.insert("tenant".into(), name.into());
                }
                if !warnings.is_empty() {
                    fields.insert(
                        "warnings".into(),
                        Json::Array(
                            warnings
                                .into_iter()
                                .map(|(_, message)| Json::Str(message))
                                .collect(),
                        ),
                    );
                }
            }
            entry
        }
        Err(error) => failure(rule, &error),
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
        .filter_map(|name| deploy::tenant(cx, &PlatformId::Bitdefender.into(), name))
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

/// The `POST /correlation-rules/v2/rules` request an Exabeam deploy would
/// send (`_exabeam_compile_preview`). The body depends on the tenant only
/// through its `test_mode`: the request shown is the first tenant's, and with
/// no tenant `testMode` is the block's, else `false`. A dry run makes no
/// call, so the name check a create starts with is not made.
fn exabeam_preview(cx: &Context<'_>, rule: &Rule, tenants: &[String]) -> Json {
    let first = tenants.iter().find_map(|name| {
        deploy::tenant(cx, &PlatformId::Exabeam.into(), name).map(|table| (name.as_str(), table))
    });
    match Exabeam::compile(cx, rule, first.map(|(_, table)| table)) {
        Ok(compiled) => {
            let mut entry = Object::new();
            entry.insert("uuid".into(), rule.uuid.clone().into());
            entry.insert("name".into(), rule.name.clone().into());
            entry.insert("api_request".into(), exabeam::create_request(&compiled));
            if let Some((name, _)) = first {
                entry.insert("tenant".into(), name.into());
            }
            Json::Object(entry)
        }
        Err(error) => failure(rule, &error),
    }
}

/// The body a Sysdig deploy would send: compiled, as the deploy compiles it
/// ([`Sysdig`]), for the first tenant the run sends the rule to, so the
/// tenant's tags are in it, and the entry names that `tenant`. With no
/// tenant, the tenant's tags are left out. The block's own policies, which
/// a deploy takes before the tenant's, are shown beside the body (they are
/// not in it), only when the block names them.
fn sysdig_preview(cx: &Context<'_>, rule: &Rule, tenants: &[String]) -> Json {
    let first = tenants.iter().find_map(|name| {
        deploy::tenant(cx, &PlatformId::Sysdig.into(), name).map(|table| (name.as_str(), table))
    });
    match Sysdig::compile(cx, rule, first.map(|(_, table)| table)) {
        Ok(sent) => {
            let mut entry = compiled(rule, Sysdig::body(&sent));
            if let Json::Object(fields) = &mut entry {
                if let Some(policies) = sent.policies {
                    fields.insert(
                        "policies".into(),
                        Json::Array(policies.into_iter().map(Json::Str).collect()),
                    );
                }
                if let Some((name, _)) = first {
                    fields.insert("tenant".into(), name.into());
                }
            }
            entry
        }
        Err(error) => failure(rule, &error),
    }
}

/// The request a Datadog deploy would send (RFC rfc-datadog-cloud-siem §7.2):
/// compiled for each tenant the run sends the rule to, so a tenant that lacks
/// a notification alias the block names fails the dry run, naming it; the
/// request shown is the first tenant's. With no tenant, an alias is shown as
/// `<tenant:notifications.ALIAS>` and the tenant's tags are left out, as
/// they are from a rule to disable, which a deploy compiles without the
/// tenant ([`Datadog`]). A dry run makes no call: the validation every write
/// starts with, and the comparison that leaves an unchanged rule alone, are
/// not made.
fn datadog_preview(cx: &Context<'_>, rule: &Rule, tenants: &[String]) -> Json {
    let reached: Vec<(&str, &Json)> = tenants
        .iter()
        .filter_map(|name| {
            deploy::tenant(cx, &PlatformId::Datadog.into(), name)
                .map(|table| (name.as_str(), table))
        })
        .collect();
    let mut first = None;
    let attempts: Vec<Option<&Json>> = if reached.is_empty() {
        vec![None]
    } else {
        reached.iter().map(|(_, table)| Some(*table)).collect()
    };
    for tenant in attempts {
        match Datadog::compile(cx, rule, tenant) {
            Ok(compiled) => {
                first.get_or_insert(compiled);
            }
            Err(error) => return failure(rule, &error),
        }
    }
    let mut entry = Object::new();
    entry.insert("uuid".into(), rule.uuid.clone().into());
    entry.insert("name".into(), rule.name.clone().into());
    entry.insert(
        "api_request".into(),
        first.map_or(Json::Null, |compiled| datadog::create_request(&compiled)),
    );
    if let Some((name, _)) = reached.first() {
        entry.insert("tenant".into(), (*name).into());
    }
    Json::Object(entry)
}

/// The preview of `rule` on `platform` (`preview_rule_deployment`), the
/// entry the dry run's `payloads` lists. Every platform but Elastic reports
/// a rule it cannot compile as a failure; Elastic shows its deploy body
/// ([`elastic_request`]) or falls back to the block's dump, and the
/// [`deployers`] show the writes a deploy sends (`requests_preview`). It
/// compiles for no tenant: [`preview_on`] compiles for the run's.
pub fn preview(cx: &Context<'_>, platform: &PlatformKey, rule: &Rule) -> Json {
    // A plugin's platform: the block's dump.
    let Some(platform_id) = platform.builtin() else {
        return dump_entry(platform.as_str(), rule);
    };
    match platform_id {
        PlatformId::Graylog => graylog_preview(cx, rule, &[]),
        // A compile error the oracle reports with the platform's display
        // name: compile_diagnostic(exc) names Sentinel.
        PlatformId::Sentinel => sentinel_entry(cx, rule, PREVIEW_TENANT, None),
        // The oracle names Sentinel in a Sysdig failure (`_compile_failure`
        // calls `compile_diagnostic(exc)` without the platform); this names
        // Sysdig (tests/golden/payloads/APPROVED.toml).
        PlatformId::Sysdig => sysdig_preview(cx, rule, &[]),
        PlatformId::Exabeam => exabeam_preview(cx, rule, &[]),
        PlatformId::Datadog => datadog_preview(cx, rule, &[]),
        // `_google_secops_compile_preview`: the `rules.create` body with what
        // the deploy reads beside it, compiled as the deploy compiles it
        // (`compiler::GoogleSecops`), or the failure, named for Google SecOps.
        PlatformId::GoogleSecops => match GoogleSecops::compile(cx, rule, ()) {
            Ok(payload) => compiled(rule, GoogleSecops::body(&payload)),
            Err(error) => failure(rule, &error),
        },
        PlatformId::Elastic => elastic_preview(cx, rule, &[]),
        deployer!() => requests_preview(cx, platform_id, rule, &[], &|_| None),
        // Shown as the block's dump with no tenant, as before #1948 made
        // this match exhaustive; `preview_on` compiles it for the run's
        // tenants (`bitdefender_preview`).
        PlatformId::Bitdefender => dump_entry(platform.as_str(), rule),
    }
}

/// The deploy body an Elastic deploy would send (`elastic_request`),
/// compiled for the first tenant the run sends the rule to, as `opentide
/// deploy` compiles it: the platform's `[[modifiers]]` for that tenant
/// applied, the tenant's `tags`, `index` and `suppression` in it, and the
/// entry naming the tenant. With no tenant, the rule is
/// compiled without one. A rule that does not compile is shown as its
/// block's dump.
fn elastic_preview(cx: &Context<'_>, rule: &Rule, tenants: &[String]) -> Json {
    let first = tenants.iter().find_map(|name| {
        deploy::tenant(cx, &PlatformId::Elastic.into(), name).map(|table| (name.as_str(), table))
    });
    let setup = first.map_or_else(elastic::Setup::none, |(_, table)| {
        elastic::Setup::from_tenant(table)
    });
    // The rule as the deploy sends it to that tenant: its modifiers applied.
    let sent = first.map(|(name, _)| {
        crate::modifiers::rule_for_tenant(
            &crate::modifiers::of_platform(cx.config, &PlatformId::Elastic.into()),
            &PlatformId::Elastic.into(),
            rule,
            name,
        )
    });
    let rule = sent.as_ref().unwrap_or(rule);
    match elastic::compile(cx, rule, &setup) {
        Ok(body) => {
            let mut entry = compiled(rule, elastic_request(rule, body));
            if let (Json::Object(fields), Some((name, _))) = (&mut entry, first) {
                fields.insert("tenant".into(), name.into());
            }
            entry
        }
        Err(_) => dump_entry("elastic", rule),
    }
}

/// What a deploy sends for an Elastic rule (`opentide deploy`'s and the
/// connectors' deploy body): the Kibana rule (`payload`), and the rule's
/// `elastic` block as the model dumps it (`block`), which the Elasticsearch
/// checks read before the rule is written.
pub fn elastic_request(rule: &Rule, payload: Json) -> Json {
    let mut request = Object::new();
    request.insert("payload".into(), payload);
    if let Some(block) = rule.block("elastic").filter(|block| block.is_filled()) {
        request.insert("block".into(), config_dump(PlatformId::Elastic, block));
    }
    Json::Object(request)
}

/// Graylog's preview (`_graylog_compile_preview`): the create request for
/// [`graylog::PREVIEW_VERSION`], compiled for every tenant the run sends the
/// rule to, so one whose tables miss an alias fails the dry run and is
/// named. The request shown is the first tenant's; with no tenant, stream
/// and notification ids are left out and `unresolved` lists the aliases.
fn graylog_preview(cx: &Context<'_>, rule: &Rule, tenants: &[String]) -> Json {
    let found: Vec<&Json> = tenants
        .iter()
        .filter_map(|name| deploy::tenant(cx, &PlatformId::Graylog.into(), name))
        .collect();
    let mut compiled = Vec::new();
    let reached: Vec<Option<&Json>> = if found.is_empty() {
        vec![None]
    } else {
        found.iter().copied().map(Some).collect()
    };
    for tenant in reached {
        match Graylog::compile(cx, rule, preview_target(tenant)) {
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

    /// The `deployer!()` pattern the exhaustive matches route on names the
    /// registry's deployers exactly, and every other built-in platform
    /// compiles offline: a new row or a changed flag fails here.
    #[test]
    fn the_deployer_pattern_is_the_registrys() {
        let (deployers, offline) = (deployers(), offline());
        for platform in PlatformId::ALL {
            let id = platform.as_str();
            assert_eq!(
                matches!(platform, deployer!()),
                deployers.contains(&platform),
                "{id}"
            );
            assert_eq!(
                !matches!(platform, deployer!()),
                offline.contains(&platform),
                "{id}"
            );
        }
    }

    #[test]
    fn a_block_dumps_in_its_models_order_with_its_defaults() {
        let block: Json = serde_json::from_str(
            r#"{"query":"q","status":"STAGING","condition":{"type":"Single Event","single_event":{"query":"q"}},"response":{"network_quarantine":true,"treat_as_threat":false}}"#,
        )
        .unwrap();
        // `query` is not a SentinelOne field: the block is shown as written.
        assert_eq!(config_dump(PlatformId::SentinelOne, &block), block);
        let Json::Object(mut valid) = block else {
            unreachable!()
        };
        valid.shift_remove("query");
        assert_eq!(
            config_dump(PlatformId::SentinelOne, &Json::Object(valid)).to_compact(),
            r#"{"enabled":false,"name":"","status":"STAGING","condition":{"type":"Single Event","single_event":{"query":"q"}},"response":{"treat_as_threat":false,"network_quarantine":true}}"#
        );
    }

    /// A Splunk block's unset fields are left out of its dump, where the
    /// oracle printed them `null`; a `null` the block writes in `advanced`
    /// is kept, since a deploy sends it to Splunk as the empty value.
    #[test]
    fn a_splunk_dump_leaves_unset_fields_out_and_keeps_an_advanced_null() {
        let block: Json = serde_json::from_str(
            r#"{"status":"STAGING","query":"index=main","advanced":{"action.x.param.tags":null,"action.x.param.title":"t"}}"#,
        )
        .unwrap();
        assert_eq!(
            config_dump(PlatformId::Splunk, &block).to_compact(),
            r#"{"enabled":false,"name":"","status":"STAGING","query":"index=main","advanced":{"action.x.param.tags":null,"action.x.param.title":"t"}}"#
        );
    }

    /// The dry run's preview of a block is its dump without `enabled` and
    /// `name` when the block does not write them (#1662, D12); every other
    /// default, which a deploy sends, stays.
    #[test]
    fn a_block_preview_leaves_out_enabled_and_name_the_block_does_not_set() {
        let block: Json = serde_json::from_str(
            r#"{"status":"STAGING","query":"index=main","advanced":{"action.x.param.tags":null}}"#,
        )
        .unwrap();
        assert_eq!(
            block_preview("splunk", &block).to_compact(),
            r#"{"status":"STAGING","query":"index=main","advanced":{"action.x.param.tags":null}}"#
        );
        let named: Json =
            serde_json::from_str(r#"{"enabled":false,"name":"N","status":"STAGING","query":"q"}"#)
                .unwrap();
        assert_eq!(
            block_preview("splunk", &named).to_compact(),
            r#"{"enabled":false,"name":"N","status":"STAGING","query":"q"}"#
        );
        // The model's other defaults stay: SentinelOne's response order and
        // members are the dump's.
        let sentinel_one: Json = serde_json::from_str(
            r#"{"status":"STAGING","condition":{"type":"Single Event","single_event":{"query":"q"}},"response":{"network_quarantine":true,"treat_as_threat":false}}"#,
        )
        .unwrap();
        assert_eq!(
            block_preview("sentinel_one", &sentinel_one).to_compact(),
            r#"{"status":"STAGING","condition":{"type":"Single Event","single_event":{"query":"q"}},"response":{"treat_as_threat":false,"network_quarantine":true}}"#
        );
        // A block the model refuses is shown as written.
        let refused: Json = serde_json::from_str(r#"{"query":"q","status":"S"}"#).unwrap();
        assert_eq!(block_preview("sentinel_one", &refused), refused);
        // A plugin's platform has no model here: its block as written,
        // `enabled` and `name` included.
        let plugin: Json =
            serde_json::from_str(r#"{"enabled":true,"name":"é😀","status":"STAGING"}"#).unwrap();
        assert_eq!(block_preview("acme_siem", &plugin), plugin);
    }
}
