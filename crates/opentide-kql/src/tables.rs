//! Generated table and ASIM catalogs: the Azure Monitor Logs table reference
//! (`data/catalogs/kql/azure-monitor/tables.toml`, `scripts/engine/sync_azure_monitor_tables.py`)
//! and the ASIM schemas and parsers (`data/catalogs/kql/asim/asim.toml`,
//! `scripts/engine/sync_asim_schemas.py`), parsed once per process.

#[cfg(test)]
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub use crate::tables_model::{
    AsimColumn, AsimParam, AsimParser, AsimSchema, AzureMonitorColumn, AzureMonitorTable,
    kusto_type,
};

/// The catalogs as the tests read them: the TOML itself, to compare with what a build
/// pre-parsed (`build.rs`, #1743).
#[cfg(test)]
fn azure_monitor_toml() -> &'static str {
    opentide_dataset::text!("data/catalogs/kql/azure-monitor/tables.toml")
}
#[cfg(test)]
fn asim_toml() -> &'static str {
    opentide_dataset::text!("data/catalogs/kql/asim/asim.toml")
}

/// The whole file, as the test reads it to compare.
#[cfg(test)]
#[derive(Debug, Deserialize)]
struct AzureMonitorFile {
    tables: Vec<AzureMonitorTable>,
}

/// The Azure Monitor Logs tables, by name: pre-parsed by `build.rs` (#1743), decoded on first use.
pub fn azure_monitor() -> &'static BTreeMap<String, AzureMonitorTable> {
    static TABLES: OnceLock<BTreeMap<String, AzureMonitorTable>> = OnceLock::new();
    TABLES.get_or_init(|| {
        opentide_dataset::compiled_value::<Vec<AzureMonitorTable>>(
            "kql-azure-monitor-tables",
            opentide_dataset::blob!("kql-azure-monitor-tables"),
        )
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

/// The ASIM schemas and parsers: pre-parsed by `build.rs` (#1743), decoded on first use.
pub fn asim() -> &'static Asim {
    static ASIM: OnceLock<Asim> = OnceLock::new();
    ASIM.get_or_init(|| {
        let (schemas, parsers) = opentide_dataset::compiled_value::<(
            Vec<AsimSchema>,
            Vec<AsimParser>,
        )>("kql-asim", opentide_dataset::blob!("kql-asim"));
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
        use opentide_core::catalog::array_items;
        let whole: AzureMonitorFile = toml::from_str(azure_monitor_toml()).unwrap();
        let items: Vec<AzureMonitorTable> = array_items(azure_monitor_toml(), "tables").unwrap();
        assert_eq!(format!("{items:?}"), format!("{:?}", whole.tables));
        assert!(items.len() > 900);
        // What the build pre-parsed (`build.rs`) is what the whole file holds, item for item.
        let pre_parsed: Vec<&AzureMonitorTable> = azure_monitor().values().collect();
        let mut whole_sorted: Vec<&AzureMonitorTable> = whole.tables.iter().collect();
        whole_sorted.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(format!("{pre_parsed:?}"), format!("{whole_sorted:?}"));
        let whole: AsimFile = toml::from_str(asim_toml()).unwrap();
        let schemas: Vec<AsimSchema> = array_items(asim_toml(), "schemas").unwrap();
        let parsers: Vec<AsimParser> = array_items(asim_toml(), "parsers").unwrap();
        assert_eq!(format!("{schemas:?}"), format!("{:?}", whole.schemas));
        assert_eq!(format!("{parsers:?}"), format!("{:?}", whole.parsers));
        let pre_parsed: Vec<&AsimSchema> = asim().schemas.values().collect();
        let mut whole_sorted: Vec<&AsimSchema> = whole.schemas.iter().collect();
        whole_sorted.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(format!("{pre_parsed:?}"), format!("{whole_sorted:?}"));
        let pre_parsed: Vec<&AsimParser> = asim().parsers.values().collect();
        let mut whole_sorted: Vec<&AsimParser> = whole.parsers.iter().collect();
        whole_sorted.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(format!("{pre_parsed:?}"), format!("{whole_sorted:?}"));
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
