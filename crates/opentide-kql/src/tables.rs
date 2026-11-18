//! Generated table and ASIM catalogs: the Azure Monitor Logs table reference
//! (`data/catalogs/kql/azure-monitor/tables.toml`, `scripts/engine/sync_azure_monitor_tables.py`)
//! and the ASIM schemas and parsers (`data/catalogs/kql/asim/asim.toml`,
//! `scripts/engine/sync_asim_schemas.py`), parsed once per process.

use opentide_core::catalog::array_items;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

const AZURE_MONITOR_TOML: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/data/catalogs/kql/azure-monitor/tables.toml"
));
const ASIM_TOML: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/data/catalogs/kql/asim/asim.toml"
));

/// The Kusto scalar types a catalog column has, each made once: tens of
/// thousands of reference columns name one of these, and a `String` each
/// was an allocation each (#1071).
const KUSTO_TYPES: [&str; 10] = [
    "bool", "datetime", "decimal", "dynamic", "guid", "int", "long", "real", "string", "timespan",
];

/// The Kusto type `name`, shared with every column of that type when it is
/// one of [`KUSTO_TYPES`]; any other is made for its column.
pub fn kusto_type(name: &str) -> Arc<str> {
    static SHARED: OnceLock<Vec<Arc<str>>> = OnceLock::new();
    let shared = SHARED.get_or_init(|| KUSTO_TYPES.iter().map(|&t| Arc::from(t)).collect());
    KUSTO_TYPES
        .iter()
        .position(|&t| t == name)
        .and_then(|i| shared.get(i))
        .map_or_else(|| Arc::from(name), Arc::clone)
}

fn interned_type<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Arc<str>, D::Error> {
    let name = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
    Ok(kusto_type(&name))
}

pub(crate) fn interned_optional_type<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Arc<str>>, D::Error> {
    let name = <Option<std::borrow::Cow<'de, str>>>::deserialize(deserializer)?;
    Ok(name.as_deref().map(kusto_type))
}

/// One table of the Azure Monitor Logs reference.
#[derive(Debug, Clone, Deserialize)]
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

/// One column of an Azure Monitor Logs table.
#[derive(Debug, Clone, Deserialize)]
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

/// The whole file, as the test reads it to compare.
#[cfg(test)]
#[derive(Debug, Deserialize)]
struct AzureMonitorFile {
    tables: Vec<AzureMonitorTable>,
}

/// The Azure Monitor Logs tables, by name.
#[expect(
    clippy::expect_used,
    reason = "parses a catalog compiled in with include_str!: a bad catalog fails the tests, never a user's document"
)]
pub fn azure_monitor() -> &'static BTreeMap<String, AzureMonitorTable> {
    static TABLES: OnceLock<BTreeMap<String, AzureMonitorTable>> = OnceLock::new();
    TABLES.get_or_init(|| {
        let tables: Vec<AzureMonitorTable> =
            array_items(AZURE_MONITOR_TOML, "tables").expect("azure-monitor/tables.toml");
        tables.into_iter().map(|t| (t.name.clone(), t)).collect()
    })
}

/// Columns every Log Analytics table has, whether or not the reference lists
/// them ([standard columns](https://learn.microsoft.com/azure/azure-monitor/logs/log-standard-columns)).
pub const STANDARD_COLUMNS: &[(&str, &str)] = &[
    ("TenantId", "string"),
    ("TimeGenerated", "datetime"),
    ("Type", "string"),
    ("SourceSystem", "string"),
    ("_ResourceId", "string"),
    ("_SubscriptionId", "string"),
    ("_BilledSize", "real"),
    ("_IsBillable", "string"),
    ("_ItemId", "string"),
    ("_TimeReceived", "datetime"),
];

/// A column a data collection rule adds to a built-in table must end in
/// `_CF`, so such a name is never an unknown column.
pub fn is_custom_column(name: &str) -> bool {
    name.ends_with("_CF")
}

/// One ASIM schema column.
#[derive(Debug, Clone, Deserialize)]
pub struct AsimColumn {
    pub name: String,
    /// The Kusto scalar type ([`kusto_type`]).
    #[serde(rename = "type", deserialize_with = "interned_type")]
    pub type_name: Arc<str>,
    /// `Mandatory`, `Recommended`, `Optional`, `Conditional` or `Alias`.
    pub class: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AsimSchema {
    pub name: String,
    pub columns: Vec<AsimColumn>,
    #[serde(default)]
    pub citation: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AsimParam {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(default)]
    pub default: Option<String>,
}

/// An ASIM parser: a function that returns rows in one schema.
#[derive(Debug, Clone, Deserialize)]
pub struct AsimParser {
    pub name: String,
    pub schema: String,
    #[serde(default)]
    pub params: Vec<AsimParam>,
    /// Unions the source parsers of its schema (`_Im_NetworkSession`).
    #[serde(default)]
    pub unifying: bool,
}

/// The whole file, as the test reads it to compare.
#[cfg(test)]
#[derive(Debug, Deserialize)]
struct AsimFile {
    schemas: Vec<AsimSchema>,
    parsers: Vec<AsimParser>,
}

pub struct Asim {
    pub schemas: BTreeMap<String, AsimSchema>,
    pub parsers: BTreeMap<String, AsimParser>,
}

#[expect(
    clippy::expect_used,
    reason = "parses a catalog compiled in with include_str!: a bad catalog fails the tests, never a user's document"
)]
pub fn asim() -> &'static Asim {
    static ASIM: OnceLock<Asim> = OnceLock::new();
    ASIM.get_or_init(|| {
        let schemas: Vec<AsimSchema> =
            array_items(ASIM_TOML, "schemas").expect("asim/asim.toml schemas");
        let parsers: Vec<AsimParser> =
            array_items(ASIM_TOML, "parsers").expect("asim/asim.toml parsers");
        Asim {
            schemas: schemas.into_iter().map(|s| (s.name.clone(), s)).collect(),
            parsers: parsers.into_iter().map(|p| (p.name.clone(), p)).collect(),
        }
    })
}

impl Asim {
    pub fn parser(&self, name: &str) -> Option<&AsimParser> {
        self.parsers.get(name)
    }

    /// The schema an ASIM parser returns.
    pub fn schema_of(&self, parser: &str) -> Option<(&str, &AsimSchema)> {
        let p = self.parser(parser)?;
        self.schemas
            .get_key_value(&p.schema)
            .map(|(k, v)| (k.as_str(), v))
    }

    pub fn citation(&self, schema: &str) -> Option<&str> {
        self.schemas.get(schema)?.citation.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR 0013: the catalogs read item by item (`opentide_core::catalog`)
    /// are what `toml` reads from the whole files, item for item (#1071).
    #[test]
    fn the_catalogs_read_item_by_item_are_the_whole_files() {
        let whole: AzureMonitorFile = toml::from_str(AZURE_MONITOR_TOML).unwrap();
        let items: Vec<AzureMonitorTable> = array_items(AZURE_MONITOR_TOML, "tables").unwrap();
        assert_eq!(format!("{items:?}"), format!("{:?}", whole.tables));
        assert!(items.len() > 900);
        let whole: AsimFile = toml::from_str(ASIM_TOML).unwrap();
        let schemas: Vec<AsimSchema> = array_items(ASIM_TOML, "schemas").unwrap();
        let parsers: Vec<AsimParser> = array_items(ASIM_TOML, "parsers").unwrap();
        assert_eq!(format!("{schemas:?}"), format!("{:?}", whole.schemas));
        assert_eq!(format!("{parsers:?}"), format!("{:?}", whole.parsers));
        assert!(schemas.len() > 10 && parsers.len() > 1000);
    }

    #[test]
    fn azure_monitor_has_sentinel_and_defender_xdr_tables() {
        let t = azure_monitor();
        for name in [
            "SigninLogs",
            "NTANetAnalytics",
            "SentinelHealth",
            "AppServiceConsoleLogs",
            "DeviceProcessEvents",
            "ASimNetworkSessionLogs",
        ] {
            assert!(
                t.get(name).and_then(|t| t.columns.as_ref()).is_some(),
                "{name}"
            );
        }
        assert!(t["AzureDiagnostics"].columns.is_none());
    }

    #[test]
    fn asim_parsers_name_their_schema() {
        let a = asim();
        for (parser, schema) in [
            ("_Im_NetworkSession", "NetworkSession"),
            ("_ASim_NetworkSession", "NetworkSession"),
            ("imNetworkSession", "NetworkSession"),
            ("ASimNetworkSession", "NetworkSession"),
            ("_ASim_Dns", "Dns"),
            ("imAuthentication", "Authentication"),
            ("_Im_ProcessCreate", "ProcessEvent"),
            ("_Im_NetworkSession_AzureFirewall", "NetworkSession"),
        ] {
            assert_eq!(
                a.schema_of(parser).map(|(s, _)| s),
                Some(schema),
                "{parser}"
            );
        }
        let (_, ns) = a.schema_of("_Im_NetworkSession").unwrap();
        let dst = ns.columns.iter().find(|c| c.name == "DstPortNumber");
        assert_eq!(dst.map(|c| &*c.type_name), Some("int"));
        // Common fields are part of every schema.
        let product = ns.columns.iter().find(|c| c.name == "EventProduct");
        assert_eq!(product.map(|c| c.class.as_str()), Some("Mandatory"));
        let im = a.parser("_Im_NetworkSession").unwrap();
        assert!(im.params.iter().any(|p| p.name == "dstportnumber"));
    }
}
