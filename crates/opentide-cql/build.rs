//! Compiles the datasets this crate carries in (#1743).
//!
//! - Every `opentide_dataset::text!("<path>")` in `src/` names a file of the shared catalogs and
//!   highlight data, which becomes a zstd blob in `OUT_DIR`, decoded once on first use.
//! - The three CQL catalogs (`data/catalogs/cql/`) are parsed here, once, into the models of
//!   `src/catalog_model.rs` and stored pre-parsed (postcard, then zstd): the first CQL query used
//!   to parse them, the larger part of its first answer.
//!
//! The files are read from the workspace root in a checkout, or else from the `assets/` copy
//! that `scripts/engine/release.py vendor` puts inside a published crate; the checkout wins, so a
//! copy left behind never shadows the real files. `OPENTIDE_ASSETS` names that root for the
//! crate's tests.

#[path = "src/catalog_model.rs"]
mod catalog_model;

use catalog_model::{Event, Field, Function};
use serde::Deserialize;

/// `functions.toml`.
#[derive(Debug, Deserialize)]
struct FunctionsFile {
    functions: Vec<Function>,
}

/// `events.toml`.
#[derive(Debug, Deserialize)]
struct EventsFile {
    #[serde(default)]
    platforms: Vec<String>,
    #[serde(default)]
    common_fields: Vec<String>,
    events: Vec<Event>,
}

/// `fields.toml`.
#[derive(Debug, Deserialize)]
struct FieldsFile {
    fields: Vec<Field>,
}

const FUNCTIONS: &str = "data/catalogs/cql/functions.toml";
const EVENTS: &str = "data/catalogs/cql/events.toml";
const FIELDS: &str = "data/catalogs/cql/fields.toml";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let datasets = opentide_dataset::build::Datasets::for_crate("data/catalogs")?;
    datasets.text_from_sources()?;

    let read = |rel: &str| {
        std::fs::read_to_string(datasets.root().join(rel))
            .map_err(|error| format!("{rel}: {error}"))
    };
    let functions: FunctionsFile =
        toml::from_str(&read(FUNCTIONS)?).map_err(|error| format!("{FUNCTIONS}: {error}"))?;
    let events: EventsFile =
        toml::from_str(&read(EVENTS)?).map_err(|error| format!("{EVENTS}: {error}"))?;
    let fields: FieldsFile =
        toml::from_str(&read(FIELDS)?).map_err(|error| format!("{FIELDS}: {error}"))?;
    datasets.value(
        "cql-catalog",
        &[FUNCTIONS, EVENTS, FIELDS],
        &(
            functions.functions,
            events.events,
            events.platforms,
            events.common_fields,
            fields.fields,
        ),
    )?;
    Ok(())
}
