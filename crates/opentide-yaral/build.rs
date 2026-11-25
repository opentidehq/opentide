//! Compiles the datasets this crate carries in (#1743).
//!
//! - Every `opentide_dataset::text!("<path>")` in `src/` names a file of the shared catalogs and
//!   highlight data, which becomes a zstd blob in `OUT_DIR`, decoded once on first use.
//! - The Unified Data Model and the function list (`data/catalogs/yaral/`) are parsed here, once,
//!   into the models of `src/catalog_model.rs` and stored pre-parsed (postcard, then zstd): the
//!   first YARA-L rule used to parse them, the larger part of its first answer.
//!
//! The files are read from the workspace root in a checkout, or else from the `assets/` copy that
//! `scripts/engine/release.py vendor` puts inside a published crate; the checkout wins, so a copy
//! left behind never shadows the real files. `OPENTIDE_ASSETS` names that root for the crate's
//! tests.

#[path = "src/catalog_model.rs"]
mod catalog_model;

use catalog_model::{EnumRow, Function, Message, Roots};
use serde::Deserialize;

const UDM: &str = "data/catalogs/yaral/udm.toml";
const FUNCTIONS: &str = "data/catalogs/yaral/functions.toml";

/// `udm.toml`.
#[derive(Deserialize)]
struct UdmFile {
    roots: Roots,
    #[serde(default)]
    free: Vec<String>,
    #[serde(default)]
    types: Vec<Message>,
    #[serde(default)]
    enums: Vec<EnumRow>,
}

/// `functions.toml`.
#[derive(Deserialize)]
struct FunctionsFile {
    #[serde(default)]
    functions: Vec<Function>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let datasets = opentide_dataset::build::Datasets::for_crate("data/catalogs")?;
    datasets.text_from_sources()?;

    let read = |rel: &str| {
        std::fs::read_to_string(datasets.root().join(rel))
            .map_err(|error| format!("{rel}: {error}"))
    };
    let udm: UdmFile = toml::from_str(&read(UDM)?).map_err(|error| format!("{UDM}: {error}"))?;
    datasets.value(
        "yaral-udm",
        &[UDM],
        &(udm.roots, udm.free, udm.types, udm.enums),
    )?;
    let functions: FunctionsFile =
        toml::from_str(&read(FUNCTIONS)?).map_err(|error| format!("{FUNCTIONS}: {error}"))?;
    datasets.value("yaral-functions", &[FUNCTIONS], &functions.functions)?;
    Ok(())
}
