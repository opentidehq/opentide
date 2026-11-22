//! Compiles the datasets this crate carries in (#1743).
//!
//! - Every `opentide_dataset::text!("<path>")` in `src/` names a file of the shared catalogs and
//!   highlight data, which becomes a zstd blob in `OUT_DIR`, decoded once on first use.
//! - The SPL catalogs (`data/catalogs/spl/`) are parsed here, once, into the models of
//!   `src/catalog_model.rs` and stored pre-parsed (postcard, then zstd): the first SPL search used
//!   to parse them, the larger part of its first answer.
//!
//! The files are read from the workspace root in a checkout, or else from the `assets/` copy that
//! `scripts/engine/release.py vendor` puts inside a published crate; the checkout wins, so a copy
//! left behind never shadows the real files. `OPENTIDE_ASSETS` names that root for the crate's
//! tests.

#[path = "src/catalog_model.rs"]
mod catalog_model;

use catalog_model::{CommandOption, CommandRow, DatamodelRow, FieldRow, FunctionRow, MacroRow};
use serde::Deserialize;

const COMMANDS: &str = "data/catalogs/spl/commands.toml";
const FIELDS: &str = "data/catalogs/spl/fields.toml";
const DATAMODELS: &str = "data/catalogs/spl/datamodels.toml";
const MACROS: &str = "data/catalogs/spl/macros.toml";
const OPTIONS: &str = "data/catalogs/spl/command-options.toml";

/// `commands.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandsFile {
    commands: Vec<CommandRow>,
    #[serde(default)]
    functions: Vec<FunctionRow>,
}

/// `fields.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldsFile {
    fields: Vec<FieldRow>,
}

/// `datamodels.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DatamodelsFile {
    /// Data models known by name only (no dataset rows).
    #[serde(default)]
    models: Vec<String>,
    datamodels: Vec<DatamodelRow>,
}

/// `macros.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MacrosFile {
    macros: Vec<MacroRow>,
}

/// `command-options.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionsFile {
    options: Vec<CommandOption>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let datasets = opentide_dataset::build::Datasets::for_crate("data/catalogs")?;
    datasets.text_from_sources()?;

    let read = |rel: &str| {
        std::fs::read_to_string(datasets.root().join(rel))
            .map_err(|error| format!("{rel}: {error}"))
    };
    let commands: CommandsFile =
        toml::from_str(&read(COMMANDS)?).map_err(|error| format!("{COMMANDS}: {error}"))?;
    let fields: FieldsFile =
        toml::from_str(&read(FIELDS)?).map_err(|error| format!("{FIELDS}: {error}"))?;
    let datamodels: DatamodelsFile =
        toml::from_str(&read(DATAMODELS)?).map_err(|error| format!("{DATAMODELS}: {error}"))?;
    let macros: MacrosFile =
        toml::from_str(&read(MACROS)?).map_err(|error| format!("{MACROS}: {error}"))?;
    let options: OptionsFile =
        toml::from_str(&read(OPTIONS)?).map_err(|error| format!("{OPTIONS}: {error}"))?;
    datasets.value(
        "spl-catalog",
        &[COMMANDS, FIELDS, DATAMODELS, MACROS, OPTIONS],
        &(
            commands.commands,
            commands.functions,
            fields.fields,
            datamodels.datamodels,
            datamodels.models,
            macros.macros,
            options.options,
        ),
    )?;
    Ok(())
}
