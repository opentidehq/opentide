//! The data model of the CQL catalogs (#1743).
//!
//! Shared by the crate (`catalog.rs` reads the models) and by its build script (`#[path]`), which
//! parses the three catalog files once and stores them pre-parsed: this file depends on `serde`
//! and on nothing else of the crate.

use serde::{Deserialize, Serialize};

/// One CQL function (`groupBy`, `array:filter`, `ioc:lookup`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the catalog's columns: one flag per fact of CrowdStrike's function reference"
)]
pub struct Function {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub category: Vec<String>,
    #[serde(default)]
    pub kind: Vec<String>,
    pub aggregate: bool,
    pub signature: Option<String>,
    pub docs: String,
    pub citation: String,
    #[serde(default)]
    pub contexts: Vec<String>,
    #[serde(default)]
    pub incompatible: Vec<String>,
    pub since: Option<String>,
    #[serde(default)]
    pub deprecated: bool,
    pub deprecated_note: Option<String>,
    #[serde(default)]
    pub removed: bool,
    pub removed_in: Option<String>,
    pub replacement: Option<String>,
    #[serde(default)]
    pub experimental: bool,
    pub feature_flag: Option<String>,
    #[serde(default)]
    pub ngsiem: bool,
    /// `false` only for a Next-Gen SIEM-only function (`remoteTable`).
    pub logscale: Option<bool>,
    #[serde(default)]
    pub unavailable: bool,
    #[serde(default)]
    pub parameters: Vec<Parameter>,
}

/// One parameter of a CQL function.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the catalog's columns: one flag per fact of CrowdStrike's parameter tables"
)]
pub struct Parameter {
    pub name: String,
    /// The catalog's type vocabulary (`field`, `string`, `integer`, `enum`, ...).
    #[serde(rename = "type")]
    pub ty: String,
    pub required: bool,
    /// The parameter whose name may be left out (at most one per function).
    pub unnamed: bool,
    /// Accepts an array `[a, b]`.
    pub multi: bool,
    /// Takes a `{ ... }` subquery or a function call.
    pub query: bool,
    pub default: Option<String>,
    #[serde(default)]
    pub values: Vec<String>,
    /// `values` are keywords and any number is also valid (`limit=max`).
    #[serde(default)]
    pub values_open: bool,
    #[serde(default)]
    pub deprecated_values: Vec<String>,
    pub min: Option<i64>,
    pub max: Option<i64>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub deprecated: bool,
    pub deprecated_since: Option<String>,
}

/// A Falcon sensor event (`#event_simpleName` value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub name: String,
    pub category: Option<String>,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub mentions: i64,
}

/// A LogScale built-in, Falcon, or CPS (ECS-based) field or tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    /// `logscale`, `falcon` or `cps`.
    pub layer: String,
    /// `metadata` (`@...`), `tag` (`#...`), `field` or `namespace`.
    pub kind: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub scope: Option<String>,
    pub docs: Option<String>,
    #[serde(default)]
    pub ecs: bool,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default)]
    pub sources: Vec<String>,
}
