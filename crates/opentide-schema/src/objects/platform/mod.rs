//! The rule platform blocks (UC-1.4, #810): `configurations.<platform>`,
//! schemas `platform::<platform>::1.0`, ported from `models/platform.py`,
//! `models/platform_configs.py` and `models/platform_schema.py`.
//!
//! Each block is one struct, its fields Pydantic's in Pydantic's order: the
//! shared ones of `PlatformConfigBase` first (`platform_block!`), then the
//! block's own. A field's doc comment is the Python docstring, so the schema's
//! description is the same text (`cargo xtask schema diff --against python`).
//!
//! | Oracle | Here |
//! |--------|------|
//! | `PlatformConfigBase._registered_platform_schema` (after) | [`check_platform_schema`] |
//! | `QueryText` (`_query_not_blank`, after) | [`check_query_text`], [`query_text`] |
//! | `ElasticConfig._validate_raw_elastic_block` (before) | [`elastic::block_codes`], the named check `elastic_rule_shape` |
//! | `SysdigConfig._validate_raw_sysdig_block` (before) | [`sysdig::block_codes`], the named check `sysdig_rule_shape` |
//! | `GraylogConfig._validate_raw_graylog_block` (before) | [`graylog::findings`], the named check `graylog_constraints`: one [`ErrorKind::Constraint`](crate::error::ErrorKind::Constraint) per finding |
//! | `SentinelTechnique` (`check_sentinel_technique`, after) | [`sentinel::check_technique`], [`sentinel::check_duration`] |
//! | `minimum_engine_version` (`ge=0`, strict) | [`sysdig::minimum_engine_version`] |
//! | `__legacy_keys__` | [`LEGACY_KEYS`] (none in the oracle: Elastic's and Sysdig's are declared empty) |
//! | `PLATFORM_CONFIG_MODELS` | [`PLATFORM_CONFIG_MODELS`], closed |
//! | `platform_schema.py` | [`schema`] |
//! | `tide.meta.deprecation` (`deprecated_field`) | [`deprecation`] |
//!
//! The named checks are Rust functions registered by name ([`NAMED_CHECKS`]);
//! each one's message is the oracle's (`ElasticConfig validation failed with
//! code(s): …`), the codes sorted and joined as Python joins them.

pub mod bitdefender;
pub mod carbon_black;
pub mod crowdstrike;
pub mod defender;
pub mod deprecation;
/// Elastic Security durations: `opentide_core::duration`, the grammar the
/// language server's advisories share.
pub use opentide_core::duration as durations;
pub mod elastic;
pub mod exabeam;
pub mod falco_text;
pub mod google_secops;
pub mod graylog;
pub mod harfanglab;
pub mod schema;
pub mod sentinel;
pub mod sentinel_one;
pub mod splunk;
pub mod sysdig;

#[cfg(test)]
mod table;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use crate::SchemaError;
use crate::configuration::repr;
use crate::from_node::{Context, FromNode};
use crate::node::{Node, Value};
use crate::objects::checks::Violation;

pub use bitdefender::BitdefenderConfig;
pub use carbon_black::CarbonBlackConfig;
pub use crowdstrike::CrowdstrikeConfig;
pub use defender::DefenderConfig;
pub use elastic::ElasticConfig;
pub use exabeam::ExabeamConfig;
pub use google_secops::GoogleSecopsConfig;
pub use google_secops::advisories::Advisory;
pub use graylog::GraylogConfig;
pub use harfanglab::HarfangLabConfig;
pub use sentinel::SentinelConfig;
pub use sentinel_one::SentinelOneConfig;
pub use splunk::SplunkConfig;
pub use sysdig::SysdigConfig;

/// Declares a platform block: the shared fields of `PlatformConfigBase`
/// (`enabled`, `name`, `schema`, `status`, `flags`, `tenants`,
/// `contributors`), in its order, then the block's own. `$identifier` is the
/// block's registered schema (`platform::sentinel::1.0`); the module declares
/// `fn platform_schema_field`, the field's conversion, with
/// [`platform_schema_field!`].
macro_rules! platform_block {
    (
        $(#[$meta:meta])*
        pub struct $name:ident [$identifier:literal] {
            $($body:tt)*
        }
    ) => {
        $(#[$meta])*
        pub struct $name {
            /// Whether this platform block is active.
            #[serde(default)]
            pub enabled: bool,
            /// Platform-specific rule name.
            #[serde(default)]
            pub name: String,
            /// Platform schema identifier, for example `platform::sentinel::1.0`.
            #[serde(
                rename = "schema",
                alias = "platform_schema",
                default,
                skip_serializing_if = "Option::is_none"
            )]
            #[schemars(extend("tide.template.required" = true))]
            #[from_node(with = "platform_schema_field")]
            #[garde(custom($crate::objects::platform::garde_platform_schema($identifier)))]
            pub platform_schema: Option<String>,
            /// Deployment status of this platform block, from the statuses in `deployment.toml`. Required:
            /// the deploy planner selects on it.
            pub status: String,
            /// Platform flags.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub flags: Option<Vec<String>>,
            /// Target tenant identifiers.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub tenants: Option<Vec<String>>,
            /// Platform contributors.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub contributors: Option<Vec<String>>,
            $($body)*
        }

        impl $crate::objects::platform::PlatformBlock for $name {
            const SCHEMA_IDENTIFIER: &'static str = $identifier;

            fn status(&self) -> &str {
                &self.status
            }

            fn enabled(&self) -> bool {
                self.enabled
            }

            fn tenants(&self) -> Option<&[String]> {
                self.tenants.as_deref()
            }
        }

        /// `schema`: the block's registered identifier, or left out.
        fn platform_schema_field(
            node: &$crate::node::Node,
            cx: &mut $crate::from_node::Context,
        ) -> Option<Option<String>> {
            $crate::objects::platform::platform_schema(node, cx, $identifier)
        }
    };
}

pub(crate) use platform_block;

/// Declares a unit enum of literal values (`Literal["a", "b"]`), each
/// `Variant = "value"`, with Pydantic's schema: `{"type": "string", "enum":
/// [...]}`, or `const` for a single value.
macro_rules! literal_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident = $value:literal,)* }) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, ::serde::Serialize, ::serde::Deserialize,
            $crate::FromNode,
        )]
        #[from_node(literal)]
        pub enum $name {
            $(
                #[doc = concat!("`", $value, "`.")]
                #[serde(rename = $value)]
                $variant,
            )*
        }

        #[cfg(feature = "python")]
        $crate::python::py_value! { $name => ::pyo3::type_hint_identifier!("builtins", "str") }

        impl ::schemars::JsonSchema for $name {
            fn schema_name() -> ::std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            // Pydantic writes a `Literal` in place, never under `$defs`; the
            // templates offer its first value only so (generate::template).
            fn inline_schema() -> bool {
                true
            }

            fn json_schema(_: &mut ::schemars::SchemaGenerator) -> ::schemars::Schema {
                $crate::objects::platform::literal_schema(&[$($value),*])
            }
        }
    };
}

pub(crate) use literal_enum;

/// Pydantic's schema of a string `Literal`: `const` for one value, else
/// `enum`.
pub(crate) fn literal_schema(values: &[&str]) -> schemars::Schema {
    match values {
        [one] => schemars::json_schema!({"type": "string", "const": one}),
        _ => schemars::json_schema!({"type": "string", "enum": values}),
    }
}

/// Pydantic's schema of an optional `Literal` (`Literal[...] | None`):
/// `anyOf` the literal and `null`. Without it, schemars folds the null into
/// the inlined literal's `enum` (`[..., null]`), which no Pydantic schema has.
pub(crate) fn optional_literal<T: schemars::JsonSchema>(
    generator: &mut schemars::SchemaGenerator,
) -> schemars::Schema {
    let literal = generator.subschema_for::<T>();
    schemars::json_schema!({"anyOf": [literal, {"type": "null"}]})
}

/// Pydantic's schema of `float`: a number, without schemars' `format`.
pub(crate) fn number_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type": "number"})
}

/// Pydantic's schema of `list[Any] | None`.
pub(crate) fn optional_any_list(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"anyOf": [{"type": "array", "items": {}}, {"type": "null"}]})
}

/// What every platform block has (`PlatformConfigBase`).
pub trait PlatformBlock {
    /// The block's registered schema identifier (`__schema_identifier__`).
    const SCHEMA_IDENTIFIER: &'static str;

    /// `status`: the deployment status the planner selects on.
    fn status(&self) -> &str;

    /// `enabled`.
    fn enabled(&self) -> bool;

    /// `tenants`, when set.
    fn tenants(&self) -> Option<&[String]>;

    /// The platform's key in `configurations` (`sentinel`): the identifier's
    /// middle part, as `platform_schema.py` takes it.
    fn platform() -> &'static str {
        Self::SCHEMA_IDENTIFIER
            .split("::")
            .nth(1)
            .unwrap_or(Self::SCHEMA_IDENTIFIER)
    }
}

/// One entry of the closed registry: the key under `configurations`, the
/// model's (Pydantic class) name, and its schema identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registered {
    /// The key under `configurations` (`sentinel`).
    pub key: &'static str,
    /// The model's name in messages (`SentinelConfig`).
    pub model: &'static str,
    /// The block's schema identifier (`platform::sentinel::1.0`).
    pub schema: &'static str,
}

/// `PLATFORM_CONFIG_MODELS`: the blocks, in the container's order. It is
/// closed: a key not listed is not a platform (`RuleConfigurations` refuses it
/// as an extra key).
pub const PLATFORM_CONFIG_MODELS: [Registered; crate::platforms::COUNT] = [
    registered::<SentinelConfig>("sentinel", "SentinelConfig"),
    registered::<DefenderConfig>("defender_for_endpoint", "DefenderConfig"),
    registered::<SplunkConfig>("splunk", "SplunkConfig"),
    registered::<SentinelOneConfig>("sentinel_one", "SentinelOneConfig"),
    registered::<CrowdstrikeConfig>("crowdstrike", "CrowdstrikeConfig"),
    registered::<HarfangLabConfig>("harfanglab", "HarfangLabConfig"),
    registered::<CarbonBlackConfig>("carbon_black_cloud", "CarbonBlackConfig"),
    registered::<ElasticConfig>("elastic", "ElasticConfig"),
    registered::<SysdigConfig>("sysdig", "SysdigConfig"),
    registered::<BitdefenderConfig>("bitdefender", "BitdefenderConfig"),
    registered::<GraylogConfig>("graylog", "GraylogConfig"),
    registered::<ExabeamConfig>("exabeam", "ExabeamConfig"),
    registered::<GoogleSecopsConfig>("google_secops", "GoogleSecopsConfig"),
];

const fn registered<T: PlatformBlock>(key: &'static str, model: &'static str) -> Registered {
    Registered {
        key,
        model,
        schema: T::SCHEMA_IDENTIFIER,
    }
}

/// The registry entry for a `configurations` key.
pub fn registered_model(key: &str) -> Option<&'static Registered> {
    PLATFORM_CONFIG_MODELS.iter().find(|entry| entry.key == key)
}

/// One model's legacy keys: each spelling and the field it fills, or `None`
/// when the key is dropped.
pub type LegacyKeys = &'static [(&'static str, Option<&'static str>)];

/// The keys a model's before-validator accepts although its schema does not
/// list them (`__legacy_keys__`), by model name: each a legacy spelling,
/// relative to the model, and the field it fills, or `None` when the key is
/// dropped. The language server's catalog reads them. In the oracle (0.23.0)
/// only `ElasticConfig` and `SysdigConfig` declare the mapping, and both
/// declare it empty: their before-validators report constraint codes and
/// accept no extra key. So no block tolerates a key, and the pre-pass
/// ([`fill_legacy_keys`]) has nothing to move.
pub const LEGACY_KEYS: &[(&str, LegacyKeys)] = &[
    ("ElasticConfig", &[]),
    ("SysdigConfig", &[]),
    ("BitdefenderConfig", &[]),
    ("ExabeamConfig", &[]),
    ("GoogleSecopsConfig", &[]),
];

/// The legacy keys of `model` ([`LEGACY_KEYS`]); a model that declares none
/// has none.
pub fn legacy_keys(model: &str) -> LegacyKeys {
    LEGACY_KEYS
        .iter()
        .find(|(name, _)| *name == model)
        .map_or(&[], |(_, keys)| *keys)
}

/// The `__legacy_keys__` pre-pass: a block with each of `model`'s legacy
/// top-level keys moved to the field it fills, unless that field is set
/// (`None` drops the key). The keys are tolerated by the model, so the
/// conversion reports nothing about them; with no key declared
/// ([`LEGACY_KEYS`]) the block is returned as it is.
pub fn fill_legacy_keys(model: &str, block: &Node) -> Node {
    let keys = legacy_keys(model);
    let Value::Map(entries) = &block.value else {
        return block.clone();
    };
    if keys.is_empty() {
        return block.clone();
    }
    let mut out: Vec<crate::node::Entry> = Vec::with_capacity(entries.len());
    for entry in entries {
        let key = entry.key.value.as_str();
        match keys.iter().find(|(legacy, _)| Some(*legacy) == key) {
            None => out.push(entry.clone()),
            Some((_, None)) => {}
            Some((_, Some(target))) => {
                let taken = entries
                    .iter()
                    .any(|other| other.key.value.as_str() == Some(target));
                if !taken {
                    out.push(crate::node::Entry {
                        key: std::sync::Arc::new(Node {
                            value: Value::Str((*target).to_owned()),
                            start: entry.key.start,
                            end: entry.key.end,
                            text: None,
                        }),
                        value: entry.value.clone(),
                    });
                }
            }
        }
    }
    Node {
        value: Value::Map(out),
        start: block.start,
        end: block.end,
        text: None,
    }
}

/// `is_legacy_external_id_key`: a vendor id key a block carried before
/// deployment state moved to `.opentide/states/deployment/` (RFC 0010):
/// `rule_id`, `rule_id_bundle` or `rule_id::<tenant>`. A block's model
/// refuses it as an extra key; `validate` reports `external_id_in_rule`
/// instead ([`is_superseded`]).
pub fn is_legacy_external_id_key(key: &str) -> bool {
    matches!(key, "rule_id" | "rule_id_bundle") || key.starts_with("rule_id::")
}

/// `is_superseded_extra_key`: a schema error at
/// `configurations.<platform>.<legacy id key>`, which `validate` leaves out
/// because `external_id_in_rule` reports the key.
pub fn is_superseded(field_path: &[String]) -> bool {
    field_path.len() == 3
        && field_path[0] == "configurations"
        && is_legacy_external_id_key(&field_path[2])
}

/// One finding of a named check that places each code: the code, its path
/// relative to the block, and what is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The constraint code (`graylog_schedule`).
    pub code: &'static str,
    /// The keys from the block to the value the finding is about.
    pub path: Vec<String>,
    /// The message.
    pub message: String,
}

/// A named check: a Rust function registered by name, run on a block's raw
/// node before its fields, giving the oracle's constraint codes.
#[derive(Debug, Clone, Copy)]
pub struct NamedCheck {
    /// The check's name (`elastic_rule_shape`).
    pub name: &'static str,
    /// The model it runs on.
    pub model: &'static str,
    /// The codes it finds on a block (sorted), empty when it passes.
    pub run: fn(&Node) -> BTreeSet<&'static str>,
    /// For a check that places each code (graylog-1.0 and the platforms after
    /// it): its findings, each reported as its own error typed by its code at
    /// its path. `None` reports the codes as one `value_error` on the block.
    pub findings: Option<fn(&Node) -> Vec<Finding>>,
}

/// The named checks, by name: `elastic_rule_shape` (rule types, removed flat
/// keys, and every other constraint of `ElasticConfig`'s before-validator)
/// and `sysdig_rule_shape` (a condition or `append_to_rule`, and every other
/// constraint of `SysdigConfig`'s), and `bitdefender_rule_shape` (the
/// bitdefender-1.0 constraint codes, which `BitdefenderConfig` reports one
/// per finding at its path, [`bitdefender::block_findings`]), and
/// `graylog_constraints` (every `graylog_*` constraint code, each at its key).
pub const NAMED_CHECKS: [NamedCheck; 4] = [
    NamedCheck {
        name: "elastic_rule_shape",
        model: "ElasticConfig",
        run: elastic::block_codes,
        findings: None,
    },
    NamedCheck {
        name: "sysdig_rule_shape",
        model: "SysdigConfig",
        run: sysdig::block_codes,
        findings: None,
    },
    NamedCheck {
        name: "graylog_constraints",
        model: "GraylogConfig",
        run: graylog::block_codes,
        findings: Some(graylog::findings),
    },
    NamedCheck {
        name: "bitdefender_rule_shape",
        model: "BitdefenderConfig",
        run: bitdefender::block_codes,
        // Its model reports each finding at its path itself
        // (`bitdefender::block_findings`).
        findings: None,
    },
];

/// Every block advisory a rule earns, each platform's in the platform
/// table's order: a warning that never rejects the rule, which `validate`
/// and `lint`'s `queries` check report at its field path. Bitdefender's
/// ([`bitdefender::advisories::advisories`]), Exabeam's
/// ([`exabeam::advisories`]), then Google SecOps'
/// ([`google_secops::advisories::advisories`]).
pub fn block_advisories(rule: &Node) -> Vec<Advisory> {
    let mut found: Vec<Advisory> = bitdefender::advisories::advisories(rule)
        .into_iter()
        .map(|advisory| Advisory {
            code: advisory.code,
            field_path: advisory.field_path,
            message: advisory.message,
        })
        .collect();
    found.extend(exabeam::advisories(rule));
    found.extend(google_secops::advisories::advisories(rule));
    found
}

/// The named check called `name`.
pub fn named_check(name: &str) -> Option<&'static NamedCheck> {
    NAMED_CHECKS.iter().find(|check| check.name == name)
}

/// The oracle's message for a before-validator's codes: `<Model> validation
/// failed with code(s): a, b`.
pub fn codes_message(model: &str, codes: &BTreeSet<&str>) -> String {
    let joined: Vec<&str> = codes.iter().copied().collect();
    format!(
        "{model} validation failed with code(s): {}",
        joined.join(", ")
    )
}

/// Runs the named check of `model` on a block's raw node as a `mode="before"`
/// model validator: a block without `status` is left to the field (a missing
/// status is "Field required", as on the other platforms); codes found are one
/// `value_error` on the block, and the block's fields are not converted.
pub(crate) fn before(model: &'static str, node: &Node, cx: &mut Context) -> bool {
    let Some(check) = NAMED_CHECKS.iter().find(|check| check.model == model) else {
        return true;
    };
    if let Some(findings) = check.findings {
        let findings = findings(node);
        for finding in &findings {
            report_finding(finding, node, cx);
        }
        return findings.is_empty();
    }
    let codes = (check.run)(node);
    if codes.is_empty() {
        return true;
    }
    Violation::value_error(codes_message(model, &codes)).report(node, cx);
    false
}

/// One finding as an error typed by its code, at its path under the block.
/// Its input is the block, as the oracle's `InitErrorDetails` gives it.
fn report_finding(finding: &Finding, block: &Node, cx: &mut Context) {
    fn at(path: &[String], finding: &Finding, block: &Node, cx: &mut Context) {
        match path.split_first() {
            None => cx.error(
                crate::error::ErrorKind::Constraint(finding.code),
                finding.message.clone(),
                block,
            ),
            Some((key, rest)) => cx.at_key(key, |cx| at(rest, finding, block, cx)),
        }
    }
    at(&finding.path, finding, block, cx);
}

/// garde: a named check on a block built in memory, through its serialised
/// form (the same function the conversion runs).
pub(crate) fn garde_named<T: serde::Serialize>(model: &'static str, block: &T) -> garde::Result {
    let Some(check) = NAMED_CHECKS.iter().find(|check| check.model == model) else {
        return Ok(());
    };
    let value = serde_json::to_value(block)
        .map_err(|error| garde::Error::new(format!("{model} does not serialise: {error}")))?;
    let node = json_node(&value);
    if let Some(findings) = check.findings {
        let findings = findings(&node);
        return match findings.first() {
            None => Ok(()),
            Some(first) => Err(garde::Error::new(format!(
                "{}: {}: {}",
                first.code,
                first.path.join("."),
                first.message
            ))),
        };
    }
    let codes = (check.run)(&node);
    if codes.is_empty() {
        Ok(())
    } else {
        Err(garde::Error::new(format!(
            "Value error, {}",
            codes_message(model, &codes)
        )))
    }
}

/// A JSON value as a node without positions.
pub(crate) fn json_node(value: &serde_json::Value) -> Node {
    use serde_json::Value as Json;
    let value = match value {
        Json::Null => Value::Null,
        Json::Bool(flag) => Value::Bool(*flag),
        Json::Number(number) => match number.as_i64() {
            Some(integer) => Value::Int(integer),
            None => Value::Float(number.as_f64().unwrap_or(f64::NAN)),
        },
        Json::String(text) => Value::Str(text.clone()),
        Json::Array(items) => Value::Seq(
            items
                .iter()
                .map(|item| std::sync::Arc::new(json_node(item)))
                .collect(),
        ),
        Json::Object(map) => Value::Map(
            map.iter()
                .map(|(key, item)| crate::node::Entry {
                    key: std::sync::Arc::new(json_node(&Json::String(key.clone()))),
                    value: std::sync::Arc::new(json_node(item)),
                })
                .collect(),
        ),
    };
    Node {
        value,
        start: crate::node::Mark::default(),
        end: crate::node::Mark::default(),
        text: None,
    }
}

/// Python's `str.isspace()` and `text.strip()`: `opentide_core::falco`'s,
/// which the language server's Sysdig findings use too.
pub use opentide_core::falco::{is_python_space, python_strip};

/// `QueryText`: a query must not be blank. Every deployer treats a falsy query
/// as "nothing to deploy" and moves on, so `query: ""` is the same silent skip
/// as no query at all.
pub fn check_query_text(value: &str) -> Result<(), Violation> {
    if python_strip(value).is_empty() {
        Err(Violation::value_error("query must not be empty"))
    } else {
        Ok(())
    }
}

/// `QueryText` in the conversion: a string, not blank.
pub fn query_text(node: &Node, cx: &mut Context) -> Option<String> {
    let value = String::from_node(node, cx)?;
    match check_query_text(&value) {
        Ok(()) => Some(value),
        Err(violation) => {
            violation.report(node, cx);
            None
        }
    }
}

/// `QueryText | None`.
pub fn optional_query_text(node: &Node, cx: &mut Context) -> Option<Option<String>> {
    if matches!(node.value, Value::Null) {
        return Some(None);
    }
    query_text(node, cx).map(Some)
}

/// garde: [`check_query_text`].
pub fn garde_query_text(value: &str, _pins: &crate::Pins) -> garde::Result {
    check_query_text(value).map_err(Violation::into_garde)
}

/// garde: [`check_query_text`] on a present value.
pub fn garde_optional_query_text(value: &Option<String>, pins: &crate::Pins) -> garde::Result {
    value
        .as_deref()
        .map_or(Ok(()), |value| garde_query_text(value, pins))
}

/// `schema` names the block's registered revision, or is left out. Nothing
/// reads the identifier at deploy, so an unregistered one (`splunk::2.1`,
/// another platform's) validated and said nothing true about the block.
pub fn check_platform_schema(value: &str, expected: &str) -> Result<(), Violation> {
    if value == expected {
        Ok(())
    } else {
        Err(Violation::value_error(format!(
            "unknown platform schema {}: this block's schema is {}",
            repr::quote(value),
            repr::quote(expected)
        )))
    }
}

/// `schema` in the conversion: `null`, or a string naming `expected`.
pub fn platform_schema(node: &Node, cx: &mut Context, expected: &str) -> Option<Option<String>> {
    if matches!(node.value, Value::Null) {
        return Some(None);
    }
    let value = String::from_node(node, cx)?;
    match check_platform_schema(&value, expected) {
        Ok(()) => Some(Some(value)),
        Err(violation) => {
            violation.report(node, cx);
            None
        }
    }
}

/// garde: [`check_platform_schema`] for a block whose identifier is
/// `expected`.
pub fn garde_platform_schema(
    expected: &'static str,
) -> impl FnOnce(&Option<String>, &crate::Pins) -> garde::Result {
    move |value, _pins| match value {
        None => Ok(()),
        Some(value) => check_platform_schema(value, expected).map_err(Violation::into_garde),
    }
}

/// A block of any platform, read on its own.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
// `allow`, not `expect`: on wasm32 (32-bit pointers) the variants are within
// the lint's limit, so an expectation would be unfulfilled there.
#[allow(
    clippy::large_enum_variant,
    reason = "one value per block read, matched at once; boxing would only add a step"
)]
#[serde(untagged)]
pub enum PlatformConfig {
    /// `sentinel`.
    Sentinel(SentinelConfig),
    /// `defender_for_endpoint`.
    Defender(DefenderConfig),
    /// `splunk`.
    Splunk(SplunkConfig),
    /// `sentinel_one`.
    SentinelOne(SentinelOneConfig),
    /// `crowdstrike`.
    Crowdstrike(CrowdstrikeConfig),
    /// `harfanglab`.
    HarfangLab(HarfangLabConfig),
    /// `carbon_black_cloud`.
    CarbonBlack(CarbonBlackConfig),
    /// `elastic`.
    Elastic(ElasticConfig),
    /// `sysdig`.
    Sysdig(SysdigConfig),
    /// `bitdefender`.
    Bitdefender(BitdefenderConfig),
    /// `exabeam`.
    Exabeam(ExabeamConfig),
    /// `google_secops`.
    GoogleSecops(GoogleSecopsConfig),
    /// `graylog`.
    Graylog(GraylogConfig),
}

/// Why [`parse_platform_config`] refused a block.
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    /// The key is not in [`PLATFORM_CONFIG_MODELS`] (`Unknown platform 'x'`).
    UnknownPlatform(String),
    /// The block's errors, at paths relative to the block.
    Invalid(Vec<SchemaError>),
}

/// `parse_platform_config`: a block of `platform`, read by its model, with the
/// errors placed relative to the block.
pub fn parse_platform_config(platform: &str, node: &Node) -> Result<PlatformConfig, ParseError> {
    fn read<T: FromNode>(
        node: &Node,
        wrap: fn(T) -> PlatformConfig,
    ) -> Result<PlatformConfig, ParseError> {
        let mut cx = Context::new();
        let value = T::from_node(node, &mut cx);
        let errors = cx.into_errors();
        match value {
            Some(value) if errors.is_empty() => Ok(wrap(value)),
            _ => Err(ParseError::Invalid(errors)),
        }
    }
    match platform {
        "sentinel" => read(node, PlatformConfig::Sentinel),
        "defender_for_endpoint" => read(node, PlatformConfig::Defender),
        "splunk" => read(node, PlatformConfig::Splunk),
        "sentinel_one" => read(node, PlatformConfig::SentinelOne),
        "crowdstrike" => read(node, PlatformConfig::Crowdstrike),
        "harfanglab" => read(node, PlatformConfig::HarfangLab),
        "carbon_black_cloud" => read(node, PlatformConfig::CarbonBlack),
        "elastic" => read(node, PlatformConfig::Elastic),
        "sysdig" => read(node, PlatformConfig::Sysdig),
        "bitdefender" => read(node, PlatformConfig::Bitdefender),
        "exabeam" => read(node, PlatformConfig::Exabeam),
        "google_secops" => read(node, PlatformConfig::GoogleSecops),
        "graylog" => read(node, PlatformConfig::Graylog),
        other => Err(ParseError::UnknownPlatform(format!(
            "Unknown platform {}",
            repr::quote(other)
        ))),
    }
}

/// Whether a block's tree, aliases counted at each use, has at most
/// [`crate::from_node::BUDGET`] nodes. A named check judges only such a
/// block: a larger one (a tree of aliases) is left to the conversion, whose
/// budget stops it with its `Limit` error, so no check walks a tree that
/// costs more than reading it may.
pub(crate) fn within_budget(node: &Node) -> bool {
    let mut remaining = crate::from_node::BUDGET;
    let mut stack: Vec<&Node> = vec![node];
    while let Some(node) = stack.pop() {
        if remaining == 0 {
            return false;
        }
        remaining -= 1;
        match &node.value {
            Value::Seq(items) => stack.extend(items.iter().map(AsRef::as_ref)),
            Value::Map(entries) => {
                for entry in entries {
                    stack.push(&entry.key);
                    stack.push(&entry.value);
                }
            }
            _ => {}
        }
    }
    true
}

/// Python's truthiness of a YAML value: `null`, `false`, `0`, `0.0`, `""`,
/// `[]` and `{}` are false.
pub(crate) fn truthy(node: Option<&Node>) -> bool {
    match node.map(|node| &node.value) {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Int(integer)) => *integer != 0,
        Some(Value::Float(float)) => *float != 0.0,
        Some(Value::Str(text) | Value::Datetime(text)) => !text.is_empty(),
        Some(Value::Seq(items)) => !items.is_empty(),
        Some(Value::Map(entries)) => !entries.is_empty(),
    }
}

/// `raw.get(key) is not None`.
pub(crate) fn present(node: Option<&Node>) -> bool {
    !matches!(node.map(|node| &node.value), None | Some(Value::Null))
}

/// `isinstance(value, int)`: an integer, or a boolean (a Python `bool` is an
/// `int`). The integer's value, a boolean as 0 or 1.
pub(crate) fn python_int(node: Option<&Node>) -> Option<i64> {
    match node.map(|node| &node.value) {
        Some(Value::Int(integer)) => Some(*integer),
        Some(Value::Bool(flag)) => Some(i64::from(*flag)),
        _ => None,
    }
}

/// A mapping's value at `key`, when the node is a mapping.
pub(crate) fn get<'n>(node: Option<&'n Node>, key: &str) -> Option<&'n Node> {
    node.and_then(|node| node.get(key)).map(AsRef::as_ref)
}

/// Whether the node is a mapping.
pub(crate) fn is_map(node: Option<&Node>) -> bool {
    matches!(node.map(|node| &node.value), Some(Value::Map(_)))
}
