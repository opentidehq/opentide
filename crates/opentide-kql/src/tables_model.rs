//! The data model of the Azure Monitor Logs table reference and the ASIM schemas, and the
//! interning of the Kusto type names their columns share (#1071).
//!
//! Shared by the crate (`tables.rs` reads the models) and by its build script
//! (`#[path]`), which parses both catalogs once and stores them pre-parsed
//! (#1743): this file depends on `serde` and `std` and on nothing else of the crate.

use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};

/// The Kusto scalar types a catalog column has, each made once: tens of
/// thousands of reference columns name one of these, and a `String` each
/// was an allocation each (#1071).
const KUSTO_TYPES: [&str; 10] = [
    "bool", "datetime", "decimal", "dynamic", "guid", "int", "long", "real", "string", "timespan",
];

/// The Kusto type `name`, shared with every column of that type when it is
/// one of the ten Kusto scalar types; any other is made for its column.
pub fn kusto_type(name: &str) -> Arc<str> {
    static SHARED: OnceLock<Vec<Arc<str>>> = OnceLock::new();
    let shared = SHARED.get_or_init(|| KUSTO_TYPES.iter().map(|&t| Arc::from(t)).collect());
    KUSTO_TYPES
        .iter()
        .position(|&t| t == name)
        .and_then(|i| shared.get(i))
        .map_or_else(|| Arc::from(name), Arc::clone)
}

/// Reads a type name straight into [`kusto_type`]: through `visit_str`, so
/// no `String` is made for it first.
pub(crate) struct TypeName;

impl serde::de::Visitor<'_> for TypeName {
    type Value = Arc<str>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a Kusto type name")
    }

    fn visit_str<E: serde::de::Error>(self, name: &str) -> Result<Arc<str>, E> {
        Ok(kusto_type(name))
    }
}

fn interned_type<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Arc<str>, D::Error> {
    deserializer.deserialize_str(TypeName)
}

/// One table of the Azure Monitor Logs reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureMonitorTable {
    pub name: String,
    #[serde(default)]
    pub docs: String,
    #[serde(default)]
    pub categories: Vec<String>,
    /// The reference page, shared by the columns of each profile (#1071).
    pub citation: Arc<str>,
    /// Every column; `None` for a table whose columns depend on what writes
    /// to it (AzureDiagnostics).
    #[serde(default)]
    pub columns: Option<Vec<AzureMonitorColumn>>,
}

/// Where the build script stored the columns of an Azure Monitor Logs table: its shard, and its
/// place in the shard (#1767). A shard is a blob of its own, decoded when the first of its tables'
/// columns is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnsAt {
    pub shard: u16,
    pub slot: u16,
}

/// An Azure Monitor Logs table without its columns, which are read on demand ([`ColumnsAt`]): all
/// the catalog needs of a table until something asks for its columns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureMonitorHead {
    pub name: String,
    pub docs: String,
    pub categories: Vec<String>,
    pub citation: Arc<str>,
    /// Where its columns are; `None` for a table whose columns depend on what writes to it
    /// (AzureDiagnostics).
    pub columns: Option<ColumnsAt>,
}

/// The tables of the reference in name order, split as the build script stores them: each table's
/// head, and its columns in `SHARDS` blobs of about [`TABLES_PER_SHARD`] tables.
#[must_use]
#[allow(
    dead_code,
    reason = "the crate's build script calls it; the crate reads what it wrote"
)]
pub fn split_azure_monitor(
    mut tables: Vec<AzureMonitorTable>,
) -> (Vec<AzureMonitorHead>, Vec<Vec<Vec<AzureMonitorColumn>>>) {
    tables.sort_by(|a, b| a.name.cmp(&b.name));
    let mut heads = Vec::with_capacity(tables.len());
    let mut shards: Vec<Vec<Vec<AzureMonitorColumn>>> = Vec::new();
    for table in tables {
        let columns = table.columns.map(|columns| {
            if shards
                .last()
                .is_none_or(|shard| shard.len() >= TABLES_PER_SHARD)
            {
                shards.push(Vec::new());
            }
            let shard = shards.len() - 1;
            let slot = shards[shard].len();
            shards[shard].push(columns);
            ColumnsAt {
                shard: u16::try_from(shard).unwrap_or(u16::MAX),
                slot: u16::try_from(slot).unwrap_or(u16::MAX),
            }
        });
        heads.push(AzureMonitorHead {
            name: table.name,
            docs: table.docs,
            categories: table.categories,
            citation: table.citation,
            columns,
        });
    }
    (heads, shards)
}

/// How many tables' columns a shard holds: small enough that the first table a query names costs
/// a fraction of the reference to decode, large enough that each shard still compresses well.
#[allow(
    dead_code,
    reason = "used by split_azure_monitor, which only the build script calls"
)]
pub const TABLES_PER_SHARD: usize = 32;

/// One column of an Azure Monitor Logs table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureMonitorColumn {
    /// Shared with the column rows each profile builds from it (#1071).
    pub name: Arc<str>,
    /// The Kusto scalar type, one of a handful shared by every column
    /// ([`kusto_type`]).
    #[serde(rename = "type", deserialize_with = "interned_type")]
    pub type_name: Arc<str>,
    /// The first sentence of the reference's description (Markdown); `None`
    /// where the reference has none or the column comes from Azure-Sentinel's
    /// validation schemas.
    #[serde(default)]
    pub description: Option<Arc<str>>,
}

/// One ASIM schema column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsimColumn {
    pub name: String,
    /// The Kusto scalar type ([`kusto_type`]).
    #[serde(rename = "type", deserialize_with = "interned_type")]
    pub type_name: Arc<str>,
    /// `Mandatory`, `Recommended`, `Optional`, `Conditional` or `Alias`.
    pub class: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsimSchema {
    pub name: String,
    pub columns: Vec<AsimColumn>,
    #[serde(default)]
    pub citation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsimParam {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(default)]
    pub default: Option<String>,
}

/// An ASIM parser: a function that returns rows in one schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsimParser {
    pub name: String,
    pub schema: String,
    #[serde(default)]
    pub params: Vec<AsimParam>,
    /// Unions the source parsers of its schema (`_Im_NetworkSession`).
    #[serde(default)]
    pub unifying: bool,
}

/// An optional [`TypeName`].
struct OptionalTypeName;

impl<'de> serde::de::Visitor<'de> for OptionalTypeName {
    type Value = Option<Arc<str>>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a Kusto type name")
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_str(TypeName).map(Some)
    }
}

/// An optional Kusto type name, interned ([`kusto_type`]).
pub(crate) fn interned_optional_type<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Arc<str>>, D::Error> {
    deserializer.deserialize_option(OptionalTypeName)
}
