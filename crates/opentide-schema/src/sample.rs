//! The conventions' worked example (ADR 0001): a two-revision family that
//! carries every derive and every field convention, so each later model has a
//! compiled, tested pattern to copy. It is not part of the Tide model: no
//! object family, file or command reads it. UC-1.3 (#809) adds the real
//! models beside it.
//!
//! What each field shows:
//!
//! | Field | Convention |
//! |-------|------------|
//! | `name` | required: no serde default, so a missing key is an error |
//! | `uuid` | an identifier kept as the string the file holds, unchecked here: a workspace check (`invalid_uuid`) owns its format, as at the oracle |
//! | `schema_id` | serialised as `schema`, also read as `schema_id` (Pydantic `alias` with `populate_by_name=True`) |
//! | `description` | `tide.*` keys as `#[schemars(extend(...))]` |
//! | `severity` | a vocabulary field: `tide.vocab`, and a custom validator that reads the [`Pins`] context |
//! | `effort` | optional (`T \| None = None`): `Option<T>`, missing or `null` read as `None`, `None` not written; a garde constraint schemars also emits. Revision 1.1 overrides it (adding `tide.template.required`) and it keeps its position, between shared groups `@0` and `@1`, as an overridden Pydantic field does |
//! | `enabled` | defaulted (`bool = True`): missing reads as the default, which is always written |
//! | `examples` | an optional list of a shared, closed sub-struct, validated with `dive` (its `description` must not be empty) |
//! | `tags` | a field only revision 1.1 has, defaulted to empty, after the inherited ones |
//!
//! Every class is `frozen` and has `eq` and `hash`, as a frozen Pydantic model
//! is hashable by its field values.

use garde::Validate;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::pins::Pins;
use crate::revision::revisions;

/// An example of a sample object: a sub-struct every revision shares as is.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Validate, FromNode,
)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[cfg_attr(
    feature = "python",
    pyo3::pyclass(frozen, get_all, eq, hash, module = "opentide_schema")
)]
#[cfg_attr(
    feature = "python",
    expect(
        clippy::unsafe_derive_deserialize,
        reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
    )
)]
pub struct SampleExample {
    /// Example description, not empty.
    #[schemars(extend("tide.template.multiline" = true))]
    #[garde(length(min = 1))]
    pub description: String,
    /// Example URL.
    #[schemars(extend("format" = "uri"))]
    #[garde(skip)]
    pub link: String,
    /// Query language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub language: Option<String>,
}

revisions! {
    shared [
        {
            /// Display name.
            #[garde(skip)]
            pub name: String,
            /// Globally unique object identifier.
            #[garde(skip)]
            pub uuid: String,
            /// Schema identifier.
            #[serde(rename = "schema", alias = "schema_id")]
            #[garde(skip)]
            pub schema_id: String,
            /// What the object is for.
            #[schemars(extend("tide.template.multiline" = true, "tide.template.spacer" = true))]
            #[garde(skip)]
            pub description: String,
            /// Alert severity, from the `alert_severity` vocabulary.
            #[schemars(extend("tide.vocab" = "alert_severity"))]
            #[garde(custom(pinned("alert_severity")))]
            pub severity: String,
        }
        {
            /// Whether the object is in use.
            #[serde(default = "default_true")]
            #[garde(skip)]
            pub enabled: bool,
            /// Example queries.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[garde(dive)]
            pub examples: Option<Vec<SampleExample>>,
        }
    ]

    /// The sample family, revision 1.0 (`sample::1.0`).
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[cfg_attr(
        feature = "python",
        pyo3::pyclass(frozen, get_all, eq, hash, module = "opentide_schema")
    )]
    #[cfg_attr(
        feature = "python",
        expect(
            clippy::unsafe_derive_deserialize,
            reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
        )
    )]
    pub struct SampleV1_0 {
        @0,
        /// Implementation effort, from 1 to 10.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[garde(range(min = 1, max = 10))]
        pub effort: Option<i64>,
        @1,
    }

    /// The sample family, revision 1.1 (`sample::1.1`): overrides `effort`,
    /// which keeps its position, and adds `tags` after the shared fields.
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[cfg_attr(
        feature = "python",
        pyo3::pyclass(frozen, get_all, eq, hash, module = "opentide_schema")
    )]
    #[cfg_attr(
        feature = "python",
        expect(
            clippy::unsafe_derive_deserialize,
            reason = "the `unsafe` is PyO3's FFI glue, which relies on no invariant of the fields"
        )
    )]
    pub struct SampleV1_1 {
        @0,
        /// Implementation effort, from 1 to 10; templates write it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(extend("tide.template.required" = true))]
        #[garde(range(min = 1, max = 10))]
        pub effort: Option<i64>,
        @1,
        /// Free-form tags.
        #[serde(default)]
        #[garde(skip)]
        pub tags: Vec<String>,
    }
}

/// The newest sample revision.
pub type Sample = SampleV1_1;

/// A forward migration is a `From` impl from one revision to the next, applied
/// in memory (plan §4, "The model"; UC-1.7, #813).
impl From<SampleV1_0> for SampleV1_1 {
    fn from(old: SampleV1_0) -> Self {
        Self {
            name: old.name,
            uuid: old.uuid,
            schema_id: "sample::1.1".to_owned(),
            description: old.description,
            severity: old.severity,
            effort: old.effort,
            enabled: old.enabled,
            examples: old.examples,
            tags: Vec::new(),
        }
    }
}

const fn default_true() -> bool {
    true
}

/// A custom validator with the context: the value's vocabulary must be pinned
/// by the revision. Which values it allows is UC-1.6's (#812) to check.
fn pinned(vocabulary: &'static str) -> impl FnOnce(&str, &Pins) -> garde::Result {
    move |_value, pins| match pins.version(vocabulary) {
        Some(_) => Ok(()),
        None => Err(garde::Error::new(format!(
            "the revision pins no version of the `{vocabulary}` vocabulary"
        ))),
    }
}
