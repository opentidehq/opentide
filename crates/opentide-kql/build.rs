//! Compiles the crate's datasets in (#1743).
//!
//! - Every `opentide_dataset::text!("<path>")` in `src/` becomes a zstd blob in `OUT_DIR`,
//!   decoded once on first use.
//! - The Azure Monitor Logs table reference (3.4 MB of TOML, the largest dataset the engine
//!   carries) and the ASIM schemas and parsers are parsed here, once, into the models of
//!   `src/tables_model.rs` and stored pre-parsed (postcard, then zstd): the first KQL query of
//!   a Sentinel or Defender workspace used to parse them, a large part of its first answer.
//!
//! The files are read from the workspace root in a checkout, or else from the `assets/` copy
//! that `scripts/engine/release.py vendor` puts inside a published crate; the checkout wins.
//! `OPENTIDE_ASSETS` names that root for the crate's tests.

#[path = "src/tables_model.rs"]
mod tables_model;

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
    Ok(())
}
