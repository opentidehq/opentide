//! The data model of the ES|QL catalogs (#1743).
//!
//! Shared by the crate (`catalog.rs` reads the models) and by its build script (`#[path]`), which
//! parses the four catalog files once and stores them pre-parsed: this file depends on `serde`
//! and on nothing else of the crate.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRow {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub syntax: String,
    #[serde(default)]
    pub docs: String,
    #[serde(default)]
    pub stack: String,
    /// Release branches that accept the command (`None`: not recorded).
    #[serde(default)]
    pub versions: Option<Vec<String>>,
    #[serde(default)]
    pub snapshot_only: bool,
    #[serde(default)]
    pub citation: Option<String>,
    #[serde(default)]
    pub alias_of: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRow {
    pub name: String,
    pub kind: String,
    pub signature: String,
    #[serde(default)]
    pub docs: String,
    #[serde(default)]
    pub returns: Vec<String>,
    /// Other registered names (`to_str` for `to_string`).
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub stack: String,
    /// Release branches that accept the function (`None`: not recorded).
    #[serde(default)]
    pub versions: Option<Vec<String>>,
    #[serde(default)]
    pub preview: bool,
    #[serde(default)]
    pub snapshot_only: bool,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub citation: Option<String>,
    #[serde(default)]
    pub example: Option<String>,
    #[serde(default)]
    pub parameters: Vec<ParamRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamRow {
    pub name: String,
    #[serde(default)]
    pub docs: String,
    #[serde(default)]
    pub types: Vec<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorRow {
    pub name: String,
    pub operator: String,
    #[serde(default)]
    pub docs: String,
    #[serde(default)]
    pub preview: bool,
    #[serde(default)]
    pub citation: Option<String>,
}

/// A `::type` cast target and the conversion function it calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeRow {
    pub name: String,
    #[serde(default)]
    pub function: String,
    #[serde(default)]
    pub versions: Vec<String>,
}
