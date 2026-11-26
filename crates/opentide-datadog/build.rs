//! Compiles the datasets this crate carries in (#1743).
//!
//! - Every `opentide_dataset::text!("<path>")` in `src/` names a file of the shared catalogs and
//!   highlight data, which becomes a zstd blob in `OUT_DIR`, decoded once on first use.
//! - The Datadog attribute catalogue (`data/catalogs/datadog/attributes.toml`) is parsed here,
//!   once, into the model of `src/catalog_model.rs` and stored pre-parsed (postcard, then zstd).
//!
//! The files are read from the workspace root in a checkout, or else from the `assets/` copy that
//! `scripts/engine/release.py vendor` puts inside a published crate; the checkout wins, so a copy
//! left behind never shadows the real files. `OPENTIDE_ASSETS` names that root for the crate's
//! tests.

#[path = "src/catalog_model.rs"]
mod catalog_model;

use catalog_model::Attribute;
use serde::Deserialize;

const ATTRIBUTES: &str = "data/catalogs/datadog/attributes.toml";

/// `attributes.toml`.
#[derive(Deserialize)]
struct AttributesFile {
    reserved: Vec<Attribute>,
    attributes: Vec<Attribute>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let datasets = opentide_dataset::build::Datasets::for_crate("data/catalogs")?;
    datasets.text_from_sources()?;
    let text = std::fs::read_to_string(datasets.root().join(ATTRIBUTES))
        .map_err(|error| format!("{ATTRIBUTES}: {error}"))?;
    let file: AttributesFile =
        toml::from_str(&text).map_err(|error| format!("{ATTRIBUTES}: {error}"))?;
    datasets.value(
        "datadog-catalog",
        &[ATTRIBUTES],
        &(file.reserved, file.attributes),
    )?;
    Ok(())
}
