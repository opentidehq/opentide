//! Compiles the datasets this crate carries in (#1743).
//!
//! - Every `opentide_dataset::text!("<path>")` in `src/` names a file of the shared catalogs and
//!   highlight data, which becomes a zstd blob in `OUT_DIR`, decoded once on first use.
//! - The three Falco catalogs (`data/catalogs/falco/`) are parsed here, once, into the models of
//!   `src/catalog_model.rs` and stored pre-parsed (postcard, then zstd): the first Falco rule
//!   used to parse them, the larger part of its first answer.
//!
//! The files are read from the workspace root in a checkout, or else from the `assets/` copy that
//! `scripts/engine/release.py vendor` puts inside a published crate; the checkout wins, so a copy
//! left behind never shadows the real files. `OPENTIDE_ASSETS` names that root for the crate's
//! tests.

// The model is public API in the crate; here its items are private, and the lint reads them so.
#[allow(
    clippy::struct_field_names,
    reason = "`Field::field_type` is the crate's public field name"
)]
#[path = "src/catalog_model.rs"]
mod catalog_model;

use catalog_model::{Event, Field, List, Macro, Param, Rule, Source};
use serde::Deserialize;

const FIELDS: &str = "data/catalogs/falco/fields.toml";
const DEFAULTS: &str = "data/catalogs/falco/defaults.toml";
const EVENTS: &str = "data/catalogs/falco/events.toml";

/// `fields.toml`.
#[derive(Deserialize)]
struct FieldsFile {
    sources: Vec<Source>,
    classes: Vec<String>,
    fields: Vec<Field>,
}

/// `defaults.toml`.
#[derive(Deserialize)]
struct DefaultsFile {
    #[serde(default)]
    macros: Vec<Macro>,
    #[serde(default)]
    lists: Vec<List>,
    #[serde(default)]
    rules: Vec<Rule>,
}

/// `events.toml`.
#[derive(Deserialize)]
struct EventsFile {
    syscalls: Vec<String>,
    events: Vec<Event>,
    params: Vec<Param>,
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
    let defaults: DefaultsFile =
        toml::from_str(&read(DEFAULTS)?).map_err(|error| format!("{DEFAULTS}: {error}"))?;
    let events: EventsFile =
        toml::from_str(&read(EVENTS)?).map_err(|error| format!("{EVENTS}: {error}"))?;
    datasets.value(
        "falco-catalog",
        &[FIELDS, DEFAULTS, EVENTS],
        &(
            fields.sources,
            fields.classes,
            fields.fields,
            defaults.macros,
            defaults.lists,
            defaults.rules,
            events.syscalls,
            events.events,
            events.params,
        ),
    )?;
    Ok(())
}
