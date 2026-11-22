//! The rows of the KQL catalogs (`data/catalogs/kql/core`, `sentinel`, `defender`): operators,
//! functions, plugins, types, options, and the hand-written tables and columns.
//!
//! Shared by the crate (`lib.rs` builds a [`Catalog`](super::Catalog) from them) and by its build
//! script (`#[path]`), which reads the TOML once and stores the rows pre-parsed (postcard, then
//! zstd, #1743): the first KQL query of a process used to parse them, about a third of its first
//! answer. This file depends on `serde`, `std` and the crate's `tables_model` and on nothing else.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamRow {
    pub name: String,
    #[serde(default)]
    pub docs: Option<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorRow {
    pub name: String,
    pub kind: String,
    pub docs: Option<String>,
    pub warning: Option<String>,
    pub citation: Option<String>,
    pub signature: Option<String>,
    #[serde(default)]
    pub parameters: Vec<ParamRow>,
    #[serde(default)]
    pub alias_of: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRow {
    pub name: String,
    pub signature: Option<String>,
    pub docs: Option<String>,
    pub kind: Option<String>,
    pub citation: Option<String>,
    #[serde(default)]
    pub parameters: Vec<ParamRow>,
    /// The function that replaces this deprecated alias.
    #[serde(default)]
    pub deprecated: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalarOperatorRow {
    pub name: String,
    pub docs: Option<String>,
    pub citation: Option<String>,
    /// The operator that replaces this legacy spelling (`containscs` → `contains_cs`).
    #[serde(default)]
    pub deprecated: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRow {
    pub name: String,
    pub docs: Option<String>,
    pub citation: Option<String>,
    pub warning: Option<String>,
    pub signature: Option<String>,
    #[serde(default)]
    pub parameters: Vec<ParamRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeRow {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableRow {
    pub name: String,
    pub profile: Option<String>,
    pub category: Option<String>,
    pub docs: Option<String>,
    pub citation: Option<String>,
    /// The catalog lists the table's documented columns (the Azure Monitor
    /// Logs reference has the table). A near miss of one is a typo.
    #[serde(default)]
    pub documented: bool,
    /// The workspace declares the table with its columns in
    /// `visibility.toml` ([`Catalog::for_workspace`](super::Catalog::for_workspace)).
    #[serde(skip)]
    pub declared: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnRow {
    /// The table's name, one allocation shared by its columns (#1071).
    pub table: Arc<str>,
    /// `sentinel` or `defender`, shared by the profile's columns.
    pub profile: Option<Arc<str>>,
    /// The column's name, shared with the reference's column it comes from.
    pub name: Arc<str>,
    /// Its Kusto type, shared by every column of that type
    /// ([`tables::kusto_type`](super::tables::kusto_type)).
    #[serde(
        default,
        rename = "type",
        deserialize_with = "super::tables_model::interned_optional_type"
    )]
    pub type_name: Option<Arc<str>>,
    /// The column's description (Markdown): hand-written, or the first
    /// sentence of the Azure Monitor Logs reference's, shared with the
    /// reference ([`tables::azure_monitor`](super::tables::azure_monitor)) and every profile (#1071).
    pub docs: Option<Arc<str>>,
    /// The table's reference page, shared by its columns.
    pub citation: Option<Arc<str>>,
    /// Added from the Azure Monitor Logs reference
    /// (`data/catalogs/kql/azure-monitor/tables.toml`), not the hand-written catalog.
    #[serde(skip)]
    pub from_reference: bool,
    /// Listed in `visibility.toml` (`[[logsources.columns]]`): a column the
    /// catalog lacks, or one whose type and description the workspace
    /// replaces ([`Catalog::for_workspace`](super::Catalog::for_workspace)).
    #[serde(skip)]
    pub declared: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorOption {
    pub operator: String,
    pub name: String,
    pub kind: Option<String>,
    #[serde(default)]
    pub values: Vec<String>,
    pub docs: Option<String>,
    pub citation: Option<String>,
    pub signature: Option<String>,
    /// Where the option is typed: `equals` (`name=`), `value` (bare enum),
    /// `token` (bare keyword in the operator prefix), `alongside` (offered with
    /// ordinary completions for the rest of the clause).
    #[serde(default)]
    pub place: Option<String>,
    /// When set, values complete inside `operator(` at this zero-based argument.
    #[serde(default)]
    pub parameter_index: Option<u32>,
}
