//! Generated table and ASIM catalogs: the Azure Monitor Logs table reference
//! (`catalogs/kql/azure-monitor/tables.toml`, `scripts/sync_azure_monitor_tables.py`)
//! and the ASIM schemas and parsers (`catalogs/kql/asim/asim.toml`,
//! `scripts/sync_asim_schemas.py`), parsed once per process.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const AZURE_MONITOR_TOML: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/catalogs/kql/azure-monitor/tables.toml"
));
const ASIM_TOML: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/catalogs/kql/asim/asim.toml"
));

/// One table of the Azure Monitor Logs reference.
#[derive(Debug, Clone, Deserialize)]
pub struct AzureMonitorTable {
    pub name: String,
    #[serde(default)]
    pub docs: String,
    #[serde(default)]
    pub categories: Vec<String>,
    pub citation: String,
    /// Every column; `None` for a table whose columns depend on what writes
    /// to it (AzureDiagnostics).
    #[serde(default)]
    pub columns: Option<Vec<AzureMonitorColumn>>,
}

/// One column of an Azure Monitor Logs table.
#[derive(Debug, Clone, Deserialize)]
pub struct AzureMonitorColumn {
    pub name: String,
    /// The Kusto scalar type.
    #[serde(rename = "type")]
    pub type_name: String,
    /// The first sentence of the reference's description (Markdown); `None`
    /// where the reference has none or the column comes from Azure-Sentinel's
    /// validation schemas.
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AzureMonitorFile {
    tables: Vec<AzureMonitorTable>,
}

/// The Azure Monitor Logs tables, by name.
pub fn azure_monitor() -> &'static BTreeMap<String, AzureMonitorTable> {
    static TABLES: OnceLock<BTreeMap<String, AzureMonitorTable>> = OnceLock::new();
    TABLES.get_or_init(|| {
        let file: AzureMonitorFile =
            toml::from_str(AZURE_MONITOR_TOML).expect("azure-monitor/tables.toml");
        file.tables
            .into_iter()
            .map(|t| (t.name.clone(), t))
            .collect()
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
    /// The Kusto scalar type.
    #[serde(rename = "type")]
    pub type_name: String,
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

#[derive(Debug, Deserialize)]
struct AsimFile {
    schemas: Vec<AsimSchema>,
    parsers: Vec<AsimParser>,
}

pub struct Asim {
    pub schemas: BTreeMap<String, AsimSchema>,
    pub parsers: BTreeMap<String, AsimParser>,
}

pub fn asim() -> &'static Asim {
    static ASIM: OnceLock<Asim> = OnceLock::new();
    ASIM.get_or_init(|| {
        let file: AsimFile = toml::from_str(ASIM_TOML).expect("asim/asim.toml");
        Asim {
            schemas: file
                .schemas
                .into_iter()
                .map(|s| (s.name.clone(), s))
                .collect(),
            parsers: file
                .parsers
                .into_iter()
                .map(|p| (p.name.clone(), p))
                .collect(),
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
        assert_eq!(dst.map(|c| c.type_name.as_str()), Some("int"));
        // Common fields are part of every schema.
        let product = ns.columns.iter().find(|c| c.name == "EventProduct");
        assert_eq!(product.map(|c| c.class.as_str()), Some("Mandatory"));
        let im = a.parser("_Im_NetworkSession").unwrap();
        assert!(im.params.iter().any(|p| p.name == "dstportnumber"));
    }
}
