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
    datasets.value("kql-azure-monitor-tables", &[AZURE_MONITOR], &azure.tables)?;

    let asim: AsimFile =
        toml::from_str(&read(ASIM)?).map_err(|error| format!("{ASIM}: {error}"))?;
    datasets.value("kql-asim", &[ASIM], &(asim.schemas, asim.parsers))?;

    let parse = |rel: String| -> Result<String, Box<dyn std::error::Error>> { Ok(read(&rel)?) };
    let core = |file: &str| parse(format!("{CORE}/{file}"));
    let operators: Operators = toml::from_str(&core("operators.toml")?)?;
    let functions: Functions = toml::from_str(&core("functions.toml")?)?;
    let scalar: ScalarOperators = toml::from_str(&core("operators-scalar.toml")?)?;
    let plugins: Plugins = toml::from_str(&core("evaluate-plugins.toml")?)?;
    let types: Types = toml::from_str(&core("types.toml")?)?;
    let options: Options = toml::from_str(&core("operator-options.toml")?)?;
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
    for (name, dir) in [("sentinel", SENTINEL), ("defender", DEFENDER)] {
        let tables_path = format!("{dir}/tables.toml");
        let columns_path = format!("{dir}/columns.toml");
        let tables: Tables = toml::from_str(&read(&tables_path)?)
            .map_err(|error| format!("{tables_path}: {error}"))?;
        let columns: Columns = toml::from_str(&read(&columns_path)?)
            .map_err(|error| format!("{columns_path}: {error}"))?;
        datasets.value(
            &format!("kql-{name}-rows"),
            &[&tables_path, &columns_path],
            &(tables.tables, columns.columns),
        )?;
    }
    Ok(())
}
