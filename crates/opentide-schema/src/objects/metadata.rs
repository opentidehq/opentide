//! Shared metadata models for Tide objects (`models/metadata.py`).

use std::collections::BTreeMap;

use garde::Validate;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

use crate::FromNode;
use crate::objects::checks;
use crate::pins::Pins;
use crate::revision::revisions;

/// The owning organisation of an object (`Organisation`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "Organisation", description = "")]
pub struct Organisation {
    /// Organisation UUID. Sharing uses it as the default publishing organisation.
    #[garde(skip)]
    pub uuid: String,
    /// Organisation display name.
    #[garde(skip)]
    pub name: String,
}

/// `version: str | int`: the business version, as the file writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, FromNode)]
#[serde(untagged)]
#[from_node(union)]
pub enum Version {
    /// A text version (`"1.2"`).
    #[from_node(tag = "str")]
    Str(String),
    /// A number (`3`).
    #[from_node(tag = "int")]
    Int(i64),
}

/// `reviewed`'s schema, as `RuleMetadata` declares it: an ISO 8601 date, a
/// datetime, the space-separated datetime the parser also accepts, or null.
fn reviewed_schema(_: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "anyOf": [
            {"type": "string", "format": "date"},
            {"type": "string", "format": "date-time"},
            {
                "type": "string",
                "pattern": r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
            },
            {"type": "null"}
        ]
    })
}

revisions! {
    shared [
        {
            /// Globally unique object identifier.
            #[garde(skip)]
            pub uuid: String,
            /// Schema identifier, for example `rule::1.0`. Selects the revision schema that validates this
            /// object.
            #[serde(rename = "schema", alias = "schema_id")]
            #[from_node(with = "checks::schema_identifier")]
            #[garde(custom(checks::garde_schema_identifier))]
            pub schema_id: String,
            /// Business version of this instance.
            #[garde(skip)]
            pub version: Version,
            /// Creation date.
            #[schemars(extend("format" = "date"))]
            #[garde(skip)]
            pub created: String,
            /// Last modification date.
            #[schemars(extend("format" = "date"))]
            #[garde(skip)]
            pub modified: String,
            /// Traffic Light Protocol classification.
            #[schemars(extend("tide.vocab" = true))]
            #[garde(skip)]
            pub tlp: String,
            /// Primary author.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[garde(skip)]
            pub author: Option<String>,
            /// Additional contributors.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[garde(skip)]
            pub contributors: Option<Vec<String>>,
            /// Owning organisation.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[garde(dive)]
            pub organisation: Option<Organisation>,
        }
    ]

    /// The metadata of every Tide object (`ObjectMetadata`).
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[schemars(rename = "ObjectMetadata", description = "")]
    #[from_node(model = "ObjectMetadata")]
    pub struct ObjectMetadata {
        @0,
    }

    /// ``rule::1.1`` metadata: optional ISO 8601 ``reviewed`` instant.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
    #[serde(deny_unknown_fields)]
    #[garde(context(Pins))]
    #[schemars(rename = "RuleMetadata")]
    #[from_node(model = "RuleMetadata")]
    pub struct RuleMetadata {
        @0,
        /// Last human review of this rule, as an ISO 8601 date or datetime. Omitted means no recorded
        /// review.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "reviewed_schema")]
        #[from_node(with = "checks::reviewed")]
        #[garde(custom(checks::garde_reviewed))]
        pub reviewed: Option<String>,
    }
}

impl ObjectMetadata {
    /// The identifier under its YAML key (`metadata.schema`).
    pub fn schema(&self) -> &str {
        &self.schema_id
    }
}

impl RuleMetadata {
    /// The identifier under its YAML key (`metadata.schema`).
    pub fn schema(&self) -> &str {
        &self.schema_id
    }
}

/// External and internal references (`ObjectReferences`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Validate, FromNode)]
#[serde(deny_unknown_fields)]
#[garde(context(Pins))]
#[schemars(rename = "ObjectReferences", description = "")]
#[from_node(model = "ObjectReferences")]
pub struct ObjectReferences {
    /// Public reference IDs to URLs (YAML int keys coerced on load).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<BTreeMap<String, String>>")]
    #[from_node(with = "checks::public_references")]
    #[garde(skip)]
    pub public: Option<BTreeMap<i64, String>>,
    /// Internal reference keys to URLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub internal: Option<BTreeMap<String, String>>,
    /// Report links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[garde(skip)]
    pub reports: Option<Vec<String>>,
}
