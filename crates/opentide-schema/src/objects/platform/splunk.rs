//! Splunk saved search, `platform::splunk::1.0` (`SplunkConfig` and its
//! nested models).

use garde::Validate;
use indexmap::IndexMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::from_node::Context;
use crate::node::{Node, Value};
use crate::objects::checks::Violation;
use crate::objects::platform::{platform_block, python_strip};
use crate::pins::Pins;

/// Declares a Splunk model whose every field is optional: `name: Type`, each
/// with its doc comment.
macro_rules! optional_model {
    (
        $(#[$meta:meta])*
        $name:ident = $model:tt {
            $( $(#[doc = $doc:literal])* $field:ident : $ty:ty, )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
        #[serde(deny_unknown_fields)]
        #[garde(context(Pins))]
        #[garde(allow_unvalidated)]
        #[schemars(rename = $model, description = "")]
        #[from_node(model = $model)]
        #[cfg_attr(
            feature = "python",
            pyo3::pyclass(frozen, get_all, eq, name = $model, module = "opentide._native.models")
        )]
        #[cfg_attr(
            feature = "python",
            expect(
                clippy::unsafe_derive_deserialize,
                reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
            )
        )]
        pub struct $name {
            $(
                $(#[doc = $doc])*
                #[serde(default, skip_serializing_if = "Option::is_none")]
                pub $field: Option<$ty>,
            )*
        }
    };
}

optional_model! {
    /// When the search runs (`SplunkSchedule`).
    SplunkSchedule = "SplunkSchedule" {
        /// `Nm`, `Nh`, or `Nd` (`5m`, `1h`, `1d`). Expected ranges are 1–59 minutes, 1–23 hours, 1–30
        /// days. Values outside the range still convert, with a warning.
        frequency: String,
        /// Cron expression. Wins over `frequency` when both are set.
        cron: String,
        /// Anchor for `frequency` when the tenant mode is `custom`. Format `HHhmm` (`09h15`). Required
        /// at deploy for that mode.
        custom_time: String,
    }
}

optional_model! {
    /// The window the search covers (`SplunkTimerange`).
    SplunkTimerange = "SplunkTimerange" {
        /// `Nm`, `Nh`, or `Nd`. Deploy converts it to a Splunk earliest time (`-90m@m`), including the
        /// tenant skew and offset.
        lookback: String,
        /// Raw Splunk earliest time. Wins over `lookback`.
        earliest: String,
        /// Raw Splunk latest time.
        latest: String,
    }
}

optional_model! {
    /// Cron or frequency, and the search time range (`SplunkScheduling`).
    SplunkScheduling = "SplunkScheduling" {
        /// `Real Time` deploys `dispatch.earliest_time` and `dispatch.latest_time` as `rt`. Any other
        /// non-empty value, or a `schedule` with no `type`, deploys `is_scheduled = 1`.
        r#type: String,
        /// Splunk `alert.expires` (`2h`, `1d`).
        expires: String,
        /// When the search runs.
        schedule: SplunkSchedule,
        /// Window the search covers.
        timerange: SplunkTimerange,
    }
}

optional_model! {
    /// Suppression window (`SplunkThrottling`).
    SplunkThrottling = "SplunkThrottling" {
        /// `alert.suppress.fields`, joined with commas.
        fields: Vec<String>,
        /// `alert.suppress.period`. When set, deploy also sets `alert.suppress` true.
        duration: String,
        /// `alert.suppress.group_name`.
        group_name: String,
    }
}

optional_model! {
    /// Alert threshold, severity, and throttling (`SplunkTrigger`).
    SplunkTrigger = "SplunkTrigger" {
        /// Splunk `counttype` (`number of events`, `number of hosts`, …).
        condition: String,
        /// Splunk `relation` (`greater than`, `less than`, …).
        comparator: String,
        /// Splunk `quantity`.
        threshold: i64,
        /// Splunk `alert.severity` (1–6). When omitted, deploy maps `response.alert_severity`.
        severity: i64,
        /// Splunk `alert_condition` search.
        custom_condition: String,
        /// `once` (any case) sets `alert.digest_mode` true. Any other value sets it false.
        r#type: String,
        /// Suppression window.
        throttling: SplunkThrottling,
    }
}

optional_model! {
    /// Notable event title and description (`SplunkNotableEvent`).
    SplunkNotableEvent = "SplunkNotableEvent" {
        /// `action.notable.param.rule_title`.
        title: String,
        /// `action.notable.param.rule_description`.
        description: String,
    }
}

optional_model! {
    /// Drilldown search name and query (`SplunkNotableDrilldown`).
    SplunkNotableDrilldown = "SplunkNotableDrilldown" {
        /// `action.notable.param.drilldown_name`.
        name: String,
        /// `action.notable.param.drilldown_search`.
        search: String,
    }
}

optional_model! {
    /// Enterprise Security notable event (`SplunkNotable`).
    SplunkNotable = "SplunkNotable" {
        /// Notable event title and description.
        event: SplunkNotableEvent,
        /// Drilldown search name and query.
        drilldown: SplunkNotableDrilldown,
        /// `action.notable.param.security_domain`, lowercased.
        security_domain: String,
    }
}

/// A risk object (`SplunkRiskObject`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SplunkRiskObject", description = "")]
#[from_node(model = "SplunkRiskObject")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SplunkRiskObject",
        module = "opentide._native.models"
    )
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct SplunkRiskObject {
    /// Result field holding the risk object.
    pub field: String,
    /// Risk object type (`system`, `user`, `other`).
    pub r#type: String,
    /// Risk score added to the object.
    pub score: i64,
}

/// A threat object (`SplunkThreatObject`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[garde(allow_unvalidated)]
#[schemars(rename = "SplunkThreatObject", description = "")]
#[from_node(model = "SplunkThreatObject")]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(
        frozen,
        get_all,
        eq,
        name = "SplunkThreatObject",
        module = "opentide._native.models"
    )
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct SplunkThreatObject {
    /// Result field holding the threat object.
    pub field: String,
    /// Threat object type (`ip_address`, `domain`, …).
    pub r#type: String,
}

optional_model! {
    /// Enterprise Security risk action (`SplunkRisk`).
    SplunkRisk = "SplunkRisk" {
        /// `action.risk.param._risk_message`.
        message: String,
        /// Each item requires `field` (string), `type` (string), and `score` (int).
        risk_objects: Vec<SplunkRiskObject>,
        /// Each item requires `field` (string) and `type` (string).
        threat_objects: Vec<SplunkThreatObject>,
    }
}

optional_model! {
    /// What an email includes (`SplunkEmailInclude`).
    SplunkEmailInclude = "SplunkEmailInclude" {
        /// `action.email.include.results_link`.
        results_link: bool,
        /// `action.email.include.search`.
        search_string: bool,
        /// `action.email.include.trigger`.
        trigger_condition: bool,
        /// `action.email.include.trigger_time`.
        trigger_time: bool,
    }
}

optional_model! {
    /// Email action (`SplunkEmail`).
    SplunkEmail = "SplunkEmail" {
        /// Recipients.
        to: String,
        /// Carbon-copy recipients.
        cc: String,
        /// Blind carbon-copy recipients.
        bcc: String,
        /// Mail priority.
        priority: String,
        /// Subject line. Deploy key `action.email.subject`.
        subject: String,
        /// Body. Deploy key `action.email.message.alert`.
        message: String,
        /// `action.email.content_type`.
        content_type: String,
        /// `action.email.sendcsv` as 1 or 0.
        send_csv: bool,
        /// `action.email.sendpdf` as 1 or 0.
        send_pdf: bool,
        /// `action.email.inline` as 1 or 0.
        inline_results: bool,
        /// What the email includes: results link, search string, trigger condition and trigger time.
        include: SplunkEmailInclude,
    }
}

optional_model! {
    /// Notable, risk, and email actions (`SplunkActions`).
    SplunkActions = "SplunkActions" {
        /// Enterprise Security notable event. Sent only when the tenant has Enterprise Security
        /// enabled.
        notable: SplunkNotable,
        /// Enterprise Security risk action. Sent only when the tenant has Enterprise Security
        /// enabled.
        risk: SplunkRisk,
        /// Email action.
        email: SplunkEmail,
    }
}

platform_block! {
    /// Splunk saved search (`SplunkConfig`).
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[garde(allow_unvalidated)]
    #[schemars(rename = "SplunkConfig", description = "")]
    #[from_node(model = "SplunkConfig")]
    #[cfg_attr(feature = "python", pyo3::pyclass(frozen, get_all, eq, name = "SplunkConfig", module = "opentide._native.models"))]
    #[cfg_attr(feature = "python", expect(clippy::unsafe_derive_deserialize, reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"))]
    pub struct SplunkConfig ["platform::splunk::1.0"] {
        /// SPL. Multiline.
        #[schemars(extend("tide.template.multiline" = true, "tide.template.spacer" = true))]
        #[from_node(with = "crate::objects::platform::query_text")]
        #[garde(custom(crate::objects::platform::garde_query_text))]
        pub query: String,
        /// Cron or frequency, and the search time range.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scheduling: Option<SplunkScheduling>,
        /// Alert threshold, severity, and throttling.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub trigger: Option<SplunkTrigger>,
        /// Notable, risk, and email actions.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<SplunkActions>,
        /// Force the Enterprise Security correlation-search action on or off. `null` follows the
        /// tenant.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub correlation_search: Option<bool>,
        /// `savedsearches.conf` keys no other field sets, sent as written at deploy: a custom alert
        /// action's `action.<name>.param.*`, for instance. A value is a string, number, boolean
        /// (`1` or `0`) or `null` (empty). A key the block also sets takes this value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(extend("tide.template.hide" = true))]
        #[from_node(with = "saved_search_table")]
        #[garde(custom(garde_saved_search_table))]
        pub advanced: Option<IndexMap<String, Option<SavedSearchValue>>>,
    }
}

/// A `savedsearches.conf` value in a Splunk block's `advanced` table:
/// `str | int | float | bool`, or `null`. Splunk stores every value as text,
/// so a list or a table has no meaning there.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, FromNode)]
#[serde(untagged)]
#[from_node(union)]
pub enum SavedSearchValue {
    /// A string.
    #[from_node(tag = "str")]
    #[schemars(description = "")]
    Text(String),
    /// An integer.
    #[from_node(tag = "int")]
    #[schemars(description = "")]
    Int(i64),
    /// A number.
    #[from_node(tag = "float")]
    #[schemars(
        description = "",
        schema_with = "crate::objects::platform::number_schema"
    )]
    Float(f64),
    /// A boolean, sent as `1` or `0`.
    #[from_node(tag = "bool")]
    #[schemars(description = "")]
    Bool(bool),
}

/// The text of a blank `advanced` key's error.
const BLANK_KEY: &str = "a savedsearches.conf key must not be empty";

/// A key of the `advanced` table must not be blank.
fn check_saved_search_key(key: &str) -> Result<(), Violation> {
    if python_strip(key).is_empty() {
        Err(Violation::value_error(BLANK_KEY))
    } else {
        Ok(())
    }
}

/// `advanced` in the conversion: `null`, or a table of scalars whose keys
/// are not blank.
#[expect(
    clippy::option_option,
    reason = "a FromNode `with` function's signature: the outer Option is the conversion's \
              success, the inner the optional field's own value (as `optional_query_text`)"
)]
fn saved_search_table(
    node: &Node,
    cx: &mut Context,
) -> Option<Option<IndexMap<String, Option<SavedSearchValue>>>> {
    if matches!(node.value, Value::Null) {
        return Some(None);
    }
    let table = IndexMap::<String, Option<SavedSearchValue>>::from_node(node, cx);
    let mut ok = true;
    if let Value::Map(entries) = &node.value {
        for entry in entries {
            if let Value::Str(key) = &entry.key.value
                && let Err(violation) = check_saved_search_key(key)
            {
                ok = false;
                cx.at_key(key, |cx| {
                    cx.at_key("[key]", |cx| violation.report(&entry.key, cx));
                });
            }
        }
    }
    let table = table?;
    ok.then_some(Some(table))
}

/// garde: [`check_saved_search_key`] on every key of a present table.
#[expect(
    clippy::ref_option,
    reason = "garde's custom validator takes the field by reference as `&Option<T>` \
              (as `garde_optional_query_text`)"
)]
fn garde_saved_search_table(
    value: &Option<IndexMap<String, Option<SavedSearchValue>>>,
    _pins: &Pins,
) -> garde::Result {
    value
        .iter()
        .flat_map(IndexMap::keys)
        .try_for_each(|key| check_saved_search_key(key).map_err(Violation::into_garde))
}
