//! Generated table and ASIM catalogs: the Azure Monitor Logs table reference
//! (`data/catalogs/kql/azure-monitor/tables.toml`, `scripts/engine/sync_azure_monitor_tables.py`)
//! and the ASIM schemas and parsers (`data/catalogs/kql/asim/asim.toml`,
//! `scripts/engine/sync_asim_schemas.py`), parsed once per process.

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
    pub name: String,
    /// The Kusto scalar type.
    #[serde(rename = "type")]
    pub type_name: String,
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

/// The items of the array of tables `[[key]]` in the generated catalog
/// `text`, each parsed on its own: `toml` builds a whole document before it
/// deserialises, and the 3.4 MB Azure Monitor reference's took tens of MiB
/// more than the tables it holds (#1071). Only one item's is alive at a
/// time here.
///
/// The catalog must be what the sync scripts write: comments and blank
/// lines, then top-level arrays of tables. Each item starts at a line
/// `[[name]]`; its sub-tables are `[name.<sub>]` or `[[name.<sub>]]`, every
/// header written exactly so (bare names, at the start of the line, nothing
/// after it); its values fit on their line (no `"""` or `'''` string).
/// Anything else is refused, never read differently from `toml`'s reading
/// of the whole file; items of another array are skipped. A test holds the
/// result to the whole file's.
///
/// # Errors
///
/// An item does not parse, or the text is not in that form.
pub(crate) fn array_items<T: serde::de::DeserializeOwned>(
    text: &str,
    key: &str,
) -> Result<Vec<T>, String> {
    let mut items = Vec::new();
    // The item being read: `Some` while in one of `key`'s, `None` in
    // another array's or before the first.
    let mut item: Option<String> = None;
    // The top-level array the last header opened, if any.
    let mut array: Option<&str> = None;
    for (number, line) in text.split_inclusive('\n').enumerate() {
        let trimmed = line.trim_end();
        let refuse = |why: &str| Err(format!("line {}: {why}: {trimmed:?}", number + 1));
        if trimmed.contains("\"\"\"") || trimmed.contains("'''") {
            return refuse("a multi-line string");
        }
        if !trimmed.trim_start().starts_with('[') {
            match item.as_mut() {
                Some(body) => body.push_str(line),
                None => {
                    let rest = trimmed.trim_start();
                    if array.is_none() && !(rest.is_empty() || rest.starts_with('#')) {
                        return refuse("not a comment before the first array item");
                    }
                }
            }
            continue;
        }
        let Some(header) = Header::of(trimmed) else {
            return refuse("not a header of the form the sync scripts write");
        };
        match header {
            Header {
                array: true,
                top,
                sub: None,
            } => {
                if let Some(done) = item.take() {
                    items.push(toml::from_str(&done).map_err(|err| err.to_string())?);
                }
                array = Some(top);
                if top == key {
                    item = Some(String::new());
                }
            }
            Header { sub: None, .. } => {
                return refuse("a top-level table, not an array item");
            }
            Header {
                array: nested,
                top,
                sub: Some(sub),
            } => {
                if array != Some(top) {
                    return refuse("a sub-table outside its array's last item");
                }
                if let Some(body) = item.as_mut() {
                    // `[[key.columns]]` is the item's own `[[columns]]`.
                    let (open, close) = if nested { ("[[", "]]") } else { ("[", "]") };
                    body.push_str(open);
                    body.push_str(sub);
                    body.push_str(close);
                    body.push('\n');
                }
            }
        }
    }
    if let Some(done) = item {
        items.push(toml::from_str(&done).map_err(|err| err.to_string())?);
    }
    Ok(items)
}

/// A table header as the sync scripts write it: `[[top]]`, `[[top.sub]]` or
/// `[top.sub]`, bare names only, the whole line.
struct Header<'a> {
    array: bool,
    top: &'a str,
    sub: Option<&'a str>,
}

impl<'a> Header<'a> {
    fn of(line: &'a str) -> Option<Self> {
        let (array, name) = match line.strip_prefix("[[") {
            Some(rest) => (true, rest.strip_suffix("]]")?),
            None => (false, line.strip_prefix('[')?.strip_suffix(']')?),
        };
        let bare = |part: &str| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        };
        let (top, sub) = match name.split_once('.') {
            Some((top, sub)) => (top, Some(sub)),
            None => (name, None),
        };
        (bare(top) && sub.is_none_or(bare)).then_some(Self { array, top, sub })
    }
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

    /// [`array_items`] reads the generated catalogs as `toml` reads the
    /// whole file, item for item (#1071).
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
        // A sub-table, an array of them, comments and the last item.
        let text = "# c\n\n[[t]]\nname = \"a\"\n[t.meta]\nx = 1\n[[t.columns]]\nname = \"c\"\n\
                    [[t.columns]]\nname = \"d\"\n# between\n[[t]]\nname = \"b\"\n";
        #[derive(Debug, Deserialize)]
        struct File {
            t: Vec<toml::Value>,
        }
        let whole: File = toml::from_str(text).unwrap();
        let items: Vec<toml::Value> = array_items(text, "t").unwrap();
        assert_eq!(items, whole.t);
        assert_eq!(items.len(), 2);
        // Another array's items, before and after, are skipped.
        let mixed = format!("[[u]]\nname = \"x\"\n[[u.sub]]\nk = 1\n{text}[[u]]\nname = \"y\"\n");
        let items: Vec<toml::Value> = array_items(&mixed, "t").unwrap();
        assert_eq!(items, whole.t);
        // What the scripts never write is refused, not read otherwise.
        for (text, why) in [
            (
                "[[t]]\nname = \"a\"\n[[t]] # c\nname = \"b\"\n",
                "trailing comment",
            ),
            (
                "[[t]]\nname = \"a\"\n[[t.columns]] # c\nname = \"c\"\n",
                "sub comment",
            ),
            ("[[ t ]]\nname = \"a\"\n", "spaces"),
            ("[[t]]\n[[ t.columns ]]\nname = \"c\"\n", "sub spaces"),
            ("[[\"t\"]]\nname = \"a\"\n", "quoted"),
            ("[[t]]\nname = \"a\"\n  [[t]]\nname = \"b\"\n", "indented"),
            ("[[t]]\ndocs = \"\"\"\n[t.x]\n\"\"\"\n", "multi-line string"),
            ("[[t]]\ndocs = '''\nx\n'''\n", "literal multi-line"),
            (
                "[[t]]\nname = \"a\"\n[[u]]\nk = 1\n[[t.columns]]\nname = \"c\"\n",
                "late sub",
            ),
            ("[t.x]\nk = 1\n[[t]]\nname = \"a\"\n", "sub before item"),
            ("[[t]]\nname = \"a\"\n[t.x.y]\nk = 1\n", "deep sub"),
        ] {
            assert!(array_items::<toml::Value>(text, "t").is_err(), "{why}");
        }
        // A top-level table that is not an array item is refused.
        assert!(array_items::<toml::Value>("[[t]]\nname = \"a\"\n[x]\nk = 1\n", "t").is_err());
        // Anything else before the first item is refused, not dropped.
        assert!(array_items::<toml::Value>("x = 1\n[[t]]\nname = \"a\"\n", "t").is_err());
        assert!(array_items::<toml::Value>("[[t]]\nname = \n", "t").is_err());
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
        assert_eq!(dst.map(|c| c.type_name.as_str()), Some("int"));
        // Common fields are part of every schema.
        let product = ns.columns.iter().find(|c| c.name == "EventProduct");
        assert_eq!(product.map(|c| c.class.as_str()), Some("Mandatory"));
        let im = a.parser("_Im_NetworkSession").unwrap();
        assert!(im.params.iter().any(|p| p.name == "dstportnumber"));
    }
}
