//! Compiles the crate's datasets in (#1743).
//!
//! - Every `opentide_dataset::text!("<path>")` in `src/` becomes a zstd blob in `OUT_DIR`,
//!   decoded once on first use.
//! - The Azure Monitor Logs table reference (3.4 MB of TOML, the largest dataset the engine
//!   carries) and the ASIM schemas and parsers are parsed here, once, into the models of
//!   `src/tables_model.rs` and stored pre-parsed (postcard, then zstd): the first KQL query of
//!   a Sentinel or Defender workspace used to parse them, a large part of its first answer.
//! - The rows of the core catalogs (`data/catalogs/kql/core`: operators, functions, plugins, types,
//!   options) and of the hand-written Sentinel and Defender tables and columns are parsed here
//!   too, into the models of `src/rows_model.rs`: building any query's catalog parsed about 40 KB
//!   of TOML for them, a third of the first KQL answer on a host with no threads (WASI, #1767).
//!
//! The files are read from the workspace root in a checkout, or else from the `assets/` copy
//! that `scripts/engine/release.py vendor` puts inside a published crate; the checkout wins.
//! `OPENTIDE_ASSETS` names that root for the crate's tests.

#[path = "src/rows_model.rs"]
#[expect(
    dead_code,
    reason = "the build script writes the rows and the crate reads them (the flags the crate sets after reading)"
)]
mod rows_model;
#[path = "src/tables_model.rs"]
mod tables_model;

use rows_model::{
    ColumnRow, FunctionRow, OperatorOption, OperatorRow, PluginRow, ScalarOperatorRow, TableRow,
    TypeRow,
};
use serde::Deserialize;
use tables_model::{AsimParser, AsimSchema, AzureMonitorTable};

const AZURE_MONITOR: &str = "data/catalogs/kql/azure-monitor/tables.toml";
const ASIM: &str = "data/catalogs/kql/asim/asim.toml";

#[derive(Deserialize)]
struct AzureMonitorFile {
    tables: Vec<AzureMonitorTable>,
}

#[derive(Deserialize)]
struct AsimFile {
    schemas: Vec<AsimSchema>,
    parsers: Vec<AsimParser>,
}

const CORE: &str = "data/catalogs/kql/core";
const SENTINEL: &str = "data/catalogs/kql/sentinel";
const DEFENDER: &str = "data/catalogs/kql/defender";

#[derive(Deserialize)]
struct Operators {
    operators: Vec<OperatorRow>,
}
#[derive(Deserialize)]
struct Functions {
    functions: Vec<FunctionRow>,
}
#[derive(Deserialize)]
struct ScalarOperators {
    scalar_operators: Vec<ScalarOperatorRow>,
}
#[derive(Deserialize)]
struct Plugins {
    plugins: Vec<PluginRow>,
}
#[derive(Deserialize)]
struct Types {
    types: Vec<TypeRow>,
}
#[derive(Deserialize)]
struct Options {
    options: Vec<OperatorOption>,
}
#[derive(Deserialize)]
struct Tables {
    tables: Vec<TableRow>,
}
#[derive(Deserialize)]
struct Columns {
    columns: Vec<ColumnRow>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let datasets = opentide_dataset::build::Datasets::for_crate("data/catalogs")?;
    datasets.text_from_sources()?;

    let read = |rel: &str| {
        std::fs::read_to_string(datasets.root().join(rel))
            .map_err(|error| format!("{rel}: {error}"))
    };
    let azure: AzureMonitorFile = toml::from_str(&read(AZURE_MONITOR)?)
        .map_err(|error| format!("{AZURE_MONITOR}: {error}"))?;
    // The tables' heads in one blob and their columns in shards of their own (#1767): the catalog
    // reads a table's columns when something asks for them.
    let reference: std::collections::BTreeMap<&str, &[tables_model::AzureMonitorColumn]> = azure
        .tables
        .iter()
        .filter_map(|table| Some((table.name.as_str(), table.columns.as_deref()?)))
        .collect();
    let (heads, shards) = tables_model::split_azure_monitor(azure.tables.clone());
    datasets.value("kql-azure-monitor-heads", &[AZURE_MONITOR], &heads)?;
    let mut shard_table = String::from("pub(crate) const SHARDS: &[ShardFn] = &[\n");
    for (index, shard) in shards.iter().enumerate() {
        let name = format!("kql-azure-monitor-columns-{index}");
        datasets.value(&name, &[AZURE_MONITOR], shard)?;
        shard_table.push_str(&format!(
            "    || opentide_dataset::value!(Vec<Vec<AzureMonitorColumn>>, {name:?}),\n"
        ));
    }
    shard_table.push_str("];\n");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").ok_or("OUT_DIR is not set")?);
    std::fs::write(out.join("kql_azure_shards.rs"), shard_table)?;

    let asim: AsimFile =
        toml::from_str(&read(ASIM)?).map_err(|error| format!("{ASIM}: {error}"))?;
    datasets.value("kql-asim", &[ASIM], &(asim.schemas, asim.parsers))?;

    // A core file that does not parse names itself, as the Azure Monitor, ASIM, Sentinel and
    // Defender ones do.
    let core = |file: &str| -> Result<String, Box<dyn std::error::Error>> {
        Ok(read(&format!("{CORE}/{file}"))?)
    };
    fn parsed<T: serde::de::DeserializeOwned>(
        file: &str,
        text: &str,
    ) -> Result<T, Box<dyn std::error::Error>> {
        toml::from_str(text).map_err(|error| format!("{CORE}/{file}: {error}").into())
    }
    let operators: Operators = parsed("operators.toml", &core("operators.toml")?)?;
    let functions: Functions = parsed("functions.toml", &core("functions.toml")?)?;
    let scalar: ScalarOperators = parsed("operators-scalar.toml", &core("operators-scalar.toml")?)?;
    let plugins: Plugins = parsed("evaluate-plugins.toml", &core("evaluate-plugins.toml")?)?;
    let types: Types = parsed("types.toml", &core("types.toml")?)?;
    let options: Options = parsed("operator-options.toml", &core("operator-options.toml")?)?;
    let core_files: Vec<String> = [
        "operators.toml",
        "functions.toml",
        "operators-scalar.toml",
        "evaluate-plugins.toml",
        "types.toml",
        "operator-options.toml",
    ]
    .iter()
    .map(|file| format!("{CORE}/{file}"))
    .collect();
    let core_files: Vec<&str> = core_files.iter().map(String::as_str).collect();
    datasets.value(
        "kql-core-rows",
        &core_files,
        &(
            operators.operators,
            functions.functions,
            scalar.scalar_operators,
            plugins.plugins,
            types.types,
            options.options,
        ),
    )?;
    let hand = |dir: &str| -> Result<(Vec<TableRow>, Vec<ColumnRow>), Box<dyn std::error::Error>> {
        let tables_path = format!("{dir}/tables.toml");
        let columns_path = format!("{dir}/columns.toml");
        let tables: Tables = toml::from_str(&read(&tables_path)?)
            .map_err(|error| format!("{tables_path}: {error}"))?;
        let columns: Columns = toml::from_str(&read(&columns_path)?)
            .map_err(|error| format!("{columns_path}: {error}"))?;
        Ok((tables.tables, columns.columns))
    };
    let reference_type = |table: &str, column: &str| {
        reference
            .get(table)?
            .iter()
            .find(|c| &*c.name == column)
            .map(|c| std::sync::Arc::clone(&c.type_name))
    };
    for (name, sentinel) in [("sentinel", true), ("defender", false)] {
        let rows =
            rows_model::profile_rows(sentinel, hand(SENTINEL)?, hand(DEFENDER)?, reference_type);
        let sources: Vec<String> = [SENTINEL, DEFENDER]
            .iter()
            .flat_map(|dir| [format!("{dir}/tables.toml"), format!("{dir}/columns.toml")])
            .collect();
        let sources: Vec<&str> = sources.iter().map(String::as_str).collect();
        datasets.value(&format!("kql-{name}-rows"), &sources, &rows)?;
    }
    Ok(())
}
