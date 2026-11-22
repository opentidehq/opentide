//! Compiles the datasets this crate carries in (#1743).
//!
//! - Every `opentide_dataset::text!("<path>")` in `src/` names a file of the shared catalogs and
//!   highlight data, which becomes a zstd blob in `OUT_DIR`, decoded once on first use.
//! - The two Exabeam catalogue files (`data/catalogs/exabeam/`) are parsed here, once, into the
//!   models of `src/catalog_model.rs` and stored pre-parsed (postcard, then zstd): the first
//!   Exabeam query used to parse them, the larger part of its first answer.
//!
//! The files are read from the workspace root in a checkout, or else from the `assets/` copy that
//! `scripts/engine/release.py vendor` puts inside a published crate; the checkout wins, so a copy
//! left behind never shadows the real files. `OPENTIDE_ASSETS` names that root for the crate's
//! tests.

#[path = "src/catalog_model.rs"]
mod catalog_model;

use catalog_model::{ActivityType, Field, Prefix, Subject};
use serde::Deserialize;

const FIELDS: &str = "data/catalogs/exabeam/fields.toml";
const VALUES: &str = "data/catalogs/exabeam/values.toml";

/// `fields.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldsFile {
    #[serde(default)]
    prefixes: Vec<Prefix>,
    #[serde(default)]
    fields: Vec<Field>,
}

/// `values.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValuesFile {
    #[serde(default)]
    outcomes: Vec<String>,
    #[serde(default)]
    subjects: Vec<Subject>,
    #[serde(default)]
    activity_types: Vec<ActivityType>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let datasets = opentide_dataset::build::Datasets::for_crate("data/catalogs")?;
    datasets.text_from_sources()?;

    let read = |rel: &str| {
        std::fs::read_to_string(datasets.root().join(rel))
            .map_err(|error| format!("{rel}: {error}"))
    };
    let fields: FieldsFile =
        toml::from_str(&read(FIELDS)?).map_err(|error| format!("{FIELDS}: {error}"))?;
    let values: ValuesFile =
        toml::from_str(&read(VALUES)?).map_err(|error| format!("{VALUES}: {error}"))?;
    datasets.value(
        "exabeam-catalog",
        &[FIELDS, VALUES],
        &(
            fields.prefixes,
            fields.fields,
            values.outcomes,
            values.subjects,
            values.activity_types,
        ),
    )?;
    Ok(())
}
