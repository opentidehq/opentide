//! Compiles the datasets this crate carries in (#1743).
//!
//! - Every `opentide_dataset::text!("<path>")` in `src/` names a file of the shared catalogs and
//!   highlight data, which becomes a zstd blob in `OUT_DIR`, decoded once on first use.
//! - The four ES|QL catalogs (`data/catalogs/esql/`) are parsed here, once, into the models of
//!   `src/catalog_model.rs` and stored pre-parsed (postcard, then zstd): the first ES|QL query
//!   used to parse them, the larger part of its first answer.
//!
//! The files are read from the workspace root in a checkout, or else from the `assets/` copy that
//! `scripts/engine/release.py vendor` puts inside a published crate; the checkout wins, so a copy
//! left behind never shadows the real files. `OPENTIDE_ASSETS` names that root for the crate's
//! tests.

#[path = "src/catalog_model.rs"]
mod catalog_model;

use catalog_model::{CommandRow, FunctionRow, OperatorRow, TypeRow};
use serde::Deserialize;

const COMMANDS: &str = "data/catalogs/esql/commands.toml";
const FUNCTIONS: &str = "data/catalogs/esql/functions.toml";
const OPERATORS: &str = "data/catalogs/esql/operators.toml";
const TYPES: &str = "data/catalogs/esql/types.toml";

/// `commands.toml`.
#[derive(Deserialize)]
struct CommandsFile {
    #[serde(default)]
    branches: Vec<String>,
    commands: Vec<CommandRow>,
}

/// `functions.toml`.
#[derive(Deserialize)]
struct FunctionsFile {
    #[serde(default)]
    branches: Vec<String>,
    functions: Vec<FunctionRow>,
}

/// `operators.toml`.
#[derive(Deserialize)]
struct OperatorsFile {
    operators: Vec<OperatorRow>,
}

/// `types.toml`.
#[derive(Deserialize)]
struct TypesFile {
    #[serde(default)]
    branches: Vec<String>,
    types: Vec<TypeRow>,
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
    let functions: FunctionsFile =
        toml::from_str(&read(FUNCTIONS)?).map_err(|error| format!("{FUNCTIONS}: {error}"))?;
    let operators: OperatorsFile =
        toml::from_str(&read(OPERATORS)?).map_err(|error| format!("{OPERATORS}: {error}"))?;
    let types: TypesFile =
        toml::from_str(&read(TYPES)?).map_err(|error| format!("{TYPES}: {error}"))?;
    if commands.branches != functions.branches || commands.branches != types.branches {
        return Err("the ES|QL catalogs name different release branches".into());
    }
    datasets.value(
        "esql-catalog",
        &[COMMANDS, FUNCTIONS, OPERATORS, TYPES],
        &(
            commands.branches,
            commands.commands,
            functions.functions,
            operators.operators,
            types.types,
        ),
    )?;
    Ok(())
}
