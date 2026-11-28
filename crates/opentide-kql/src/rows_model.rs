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
    /// The one dialect that has the function (`defender`: advanced hunting's own,
    /// `data/catalogs/kql/defender/functions.toml`); `None` for Kusto's, which every dialect has.
    #[serde(default)]
    pub profile: Option<String>,
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

/// A profile's hand-written tables and columns: [`Catalog::with_profile`](super::Catalog::with_profile)
/// starts from them (`Sentinel` has the Sentinel rows and the Defender rows, `Defender` the
/// Defender ones), and the lazily read reference columns come after.
///
/// Where a hand-written column's type disagrees with the reference's for the same column of the
/// same table, neither is trusted for type checks: its type is dropped. The reference's types are
/// what `reference_type(table, column)` says, `None` for a table the reference lists no columns of
/// or a column it does not have. Settled here, once, because it reads the reference's columns of
/// every table that has a hand-written one, which a catalog no longer reads in full (#1767). A
/// column written twice settles its last row, the one a lookup by `(table, name)` finds.
#[allow(
    dead_code,
    reason = "the crate's build script calls it and the crate's tests; the crate itself reads the rows it wrote"
)]
pub fn profile_rows(
    sentinel: bool,
    sentinel_rows: (Vec<TableRow>, Vec<ColumnRow>),
    defender_rows: (Vec<TableRow>, Vec<ColumnRow>),
    reference_type: impl Fn(&str, &str) -> Option<Arc<str>>,
) -> (Vec<TableRow>, Vec<ColumnRow>) {
    let mut tables = Vec::new();
    let mut columns = Vec::new();
    if sentinel {
        tables.extend(sentinel_rows.0);
        columns.extend(sentinel_rows.1);
    }
    let (defender_tables, defender_columns) = defender_rows;
    for table in defender_tables {
        if !tables.iter().any(|t: &TableRow| t.name == table.name) {
            tables.push(table);
        }
    }
    columns.extend(defender_columns);
    let mut last: std::collections::HashMap<(Arc<str>, Arc<str>), usize> =
        std::collections::HashMap::new();
    for (i, column) in columns.iter().enumerate() {
        last.insert((Arc::clone(&column.table), Arc::clone(&column.name)), i);
    }
    for ((table, name), i) in last {
        if let Some(listed) = reference_type(&table, &name)
            && let Some(column) = columns.get_mut(i)
            && column.type_name.as_deref() != Some(&*listed)
        {
            column.type_name = None;
        }
    }
    (tables, columns)
}
