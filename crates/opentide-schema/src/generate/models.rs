//! What a generator needs of a model beyond its JSON Schema: the order of
//! its fields.
//!
//! The workspace's `serde_json` keeps object keys sorted (ADR 0001, "Do
//! not" turn on `preserve_order`), so a schema schemars derives has lost the
//! order the struct declares its fields in, which is the order Pydantic
//! writes them in and templates render them in. serde keeps it: a derived
//! `Deserialize` hands the field names, in declaration order and as
//! serialised, to `Deserializer::deserialize_struct`. [`field_order`] reads
//! them there with a deserializer that stops at that call.
//!
//! [`models`] names every model a generated artifact walks, by its schema
//! name (the `$defs` key); `generate::tests` fails when a schema reaches a
//! model it does not name, or when a model's fields are not its schema's
//! properties.

use std::borrow::Cow;
use std::fmt;
use std::sync::OnceLock;

use schemars::JsonSchema;
use serde::de::{self, Deserialize, Deserializer, Visitor};

use crate::objects::{metadata, objective, platform, response, rule, threat};

/// Stops a deserialization once [`Capture`] has what it came for.
#[derive(Debug)]
struct Stop;

impl fmt::Display for Stop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("field order captured")
    }
}

impl std::error::Error for Stop {}

impl de::Error for Stop {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Self
    }
}

/// A deserializer that records the field names `deserialize_struct` is
/// given, and deserializes nothing.
struct Capture<'a>(&'a mut Option<&'static [&'static str]>);

impl<'de> Deserializer<'de> for Capture<'_> {
    type Error = Stop;

    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Stop> {
        Err(Stop)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Stop> {
        *self.0 = Some(fields);
        Err(Stop)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map enum identifier ignored_any
    }
}

/// `T`'s field names, in declaration order and as serialised, each with its
/// aliases beside it, if `T`'s `Deserialize` is serde's derive for a struct with
/// named fields.
pub fn field_order<T: for<'de> Deserialize<'de>>() -> Option<&'static [&'static str]> {
    let mut fields = None;
    let _ = T::deserialize(Capture(&mut fields));
    fields
}

/// A model a generator walks.
#[derive(Debug, Clone)]
pub struct Model {
    /// Its schema name: the `$defs` key, and its `title`.
    pub name: Cow<'static, str>,
    /// Its fields, in declaration order, as serialised, each with its
    /// aliases beside it (serde lists them so).
    pub fields: &'static [&'static str],
    /// Whether it is object metadata (`ObjectMetadata` and its revisions),
    /// whose keys `lint.toml` can require.
    pub metadata: bool,
}

fn model<T: JsonSchema + for<'de> Deserialize<'de>>(metadata: bool) -> Model {
    Model {
        name: T::schema_name(),
        fields: field_order::<T>().unwrap_or(&[]),
        metadata,
    }
}

macro_rules! models {
    ($($ty:ty),* $(,)?) => {
        vec![$(model::<$ty>(false)),*]
    };
}

/// Every model the object and platform templates and schemas reach.
pub fn models() -> &'static [Model] {
    static MODELS: OnceLock<Vec<Model>> = OnceLock::new();
    MODELS.get_or_init(|| {
        use platform::{
            carbon_black, crowdstrike, defender, elastic, google_secops, graylog, harfanglab,
            sentinel, sentinel_one, splunk, sysdig,
        };
        let mut all = vec![
            model::<metadata::ObjectMetadata>(true),
            model::<metadata::RuleMetadata>(true),
        ];
        all.extend(models![
            metadata::Organisation,
            metadata::ObjectReferences,
            response::ResponseSearch,
            response::ResponseProcedure,
            response::RuleResponse,
            rule::RuleConfigurations,
            rule::RuleV1_0,
            rule::RuleV1_1,
            threat::ThreatActor,
            threat::ThreatBody,
            threat::ThreatVectorV1_0,
            objective::SignalData,
            objective::ExternalDetector,
            objective::DetectionExample,
            objective::DetectionSignal,
            objective::ObjectiveComposition,
            objective::ObjectiveBody,
            objective::ObjectiveV1_0,
            carbon_black::CarbonBlackConfig,
            crowdstrike::CrowdstrikeDetails,
            crowdstrike::CrowdstrikeSchedule,
            crowdstrike::CrowdstrikeConfig,
            defender::DefenderAlert,
            defender::DefenderImpactedEntities,
            defender::DefenderGroupScoping,
            defender::DefenderAllowBlockGroupScoping,
            defender::DefenderAllowBlockAction,
            defender::DefenderFileActions,
            defender::DefenderDeviceActions,
            defender::DefenderUserActions,
            defender::DefenderResponseActions,
            defender::DefenderExclusion,
            defender::DefenderConfig,
            elastic::ElasticConfig,
            elastic::ElasticSuppression,
            elastic::ElasticCardinality,
            elastic::ElasticThreshold,
            elastic::ElasticRequiredField,
            elastic::ElasticIntegration,
            elastic::ElasticSeverityMapping,
            elastic::ElasticRiskScoreMapping,
            elastic::ElasticThreatEntry,
            elastic::ElasticThreatGroup,
            elastic::ElasticScheduling,
            elastic::ElasticSeverity,
            elastic::ElasticRisk,
            elastic::ElasticOverrides,
            elastic::ElasticGuide,
            elastic::ElasticExceptionList,
            elastic::ElasticExceptions,
            elastic::ElasticTimeline,
            elastic::ElasticActions,
            elastic::ElasticFilter,
            elastic::ElasticEql,
            elastic::ElasticNewTerms,
            elastic::ElasticThreatMatch,
            elastic::ElasticMachineLearning,
            harfanglab::HarfangLabSigmaLogSource,
            harfanglab::HarfangLabSigmaSelection,
            harfanglab::HarfangLabSigma,
            harfanglab::HarfangLabYaraMeta,
            harfanglab::HarfangLabYara,
            harfanglab::HarfangLabConfig,
            sentinel::SentinelTemplate,
            sentinel::SentinelTrigger,
            sentinel::SentinelScheduling,
            sentinel::SentinelCustomDetails,
            sentinel::SentinelDynamicProperties,
            sentinel::SentinelAlert,
            sentinel::SentinelAlertGrouping,
            sentinel::SentinelGrouping,
            sentinel::SentinelMappingEntry,
            sentinel::SentinelEntityMapping,
            sentinel::SentinelExclusion,
            sentinel::SentinelConfig,
            sentinel_one::SentinelOneDetails,
            sentinel_one::SentinelOneSingleEvent,
            sentinel_one::SentinelOneSubQuery,
            sentinel_one::SentinelOneCorrelation,
            sentinel_one::SentinelOneCondition,
            sentinel_one::SentinelOneResponse,
            sentinel_one::SentinelOneConfig,
            splunk::SplunkRiskObject,
            splunk::SplunkThreatObject,
            splunk::SplunkConfig,
            splunk::SplunkSchedule,
            splunk::SplunkTimerange,
            splunk::SplunkScheduling,
            splunk::SplunkThrottling,
            splunk::SplunkTrigger,
            splunk::SplunkNotableEvent,
            splunk::SplunkNotableDrilldown,
            splunk::SplunkNotable,
            splunk::SplunkRisk,
            splunk::SplunkEmailInclude,
            splunk::SplunkEmail,
            splunk::SplunkActions,
            sysdig::SysdigException,
            sysdig::SysdigMacro,
            sysdig::SysdigList,
            sysdig::SysdigConfig,
            google_secops::GoogleSecopsMatch,
            google_secops::GoogleSecopsOptions,
            google_secops::GoogleSecopsSchedule,
            google_secops::GoogleSecopsConfig,
            graylog::GraylogSchedule,
            graylog::GraylogAggregation,
            graylog::GraylogEventTemplate,
            graylog::GraylogLookupTable,
            graylog::GraylogEventLookup,
            graylog::GraylogConfig,
        ]);
        all
    })
}

/// The model of schema name `name`.
pub fn model_named(name: &str) -> Option<&'static Model> {
    models().iter().find(|model| model.name == name)
}

/// Map fields whose keys are integers (`dict[int, str]`): JSON Schema writes
/// a map's keys as strings, so the schema does not say. `(model, field)`;
/// `generate::tests` checks each against its model.
pub const INTEGER_KEYED: &[(&str, &str)] = &[("ObjectReferences", "public")];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_order_is_the_declaration_order_as_serialised() {
        let fields = field_order::<threat::ThreatActor>().unwrap();
        assert_eq!(fields, &["name", "sighting", "references"]);
        let block = field_order::<sentinel_block::SentinelConfig>().unwrap();
        // `platform_schema` serialises as `schema`, after `name`, its alias
        // beside it.
        assert_eq!(
            &block[..5],
            &["enabled", "name", "platform_schema", "schema", "status"]
        );
    }

    use crate::objects::platform::sentinel as sentinel_block;

    #[test]
    fn field_order_is_none_for_a_type_that_is_not_a_struct() {
        assert_eq!(field_order::<String>(), None);
        assert_eq!(field_order::<threat::Killchain>(), None);
    }

    #[test]
    fn every_model_is_named_once_and_has_fields() {
        let mut names: Vec<&str> = models().iter().map(|model| &*model.name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "a schema name is listed twice");
        for model in models() {
            assert!(
                !model.fields.is_empty(),
                "{} has no field order",
                model.name
            );
        }
    }
}
