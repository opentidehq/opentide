//! Compiles the datasets this crate carries in (#1743).
//!
//! - Every `opentide_dataset::text!("<path>")` in `src/` names a file of the shared catalogs and
//!   highlight data, which becomes a zstd blob in `OUT_DIR`, decoded once on first use.
//! - The YARA module catalogue and language data (`data/catalogs/yara/`) are parsed here, once,
//!   into the models of `src/catalog_model.rs` and stored pre-parsed (postcard, then zstd): the
//!   first YARA rule used to parse them, the larger part of its first answer.
//!
//! The files are read from the workspace root in a checkout, or else from the `assets/` copy that
//! `scripts/engine/release.py vendor` puts inside a published crate; the checkout wins, so a copy
//! left behind never shadows the real files. `OPENTIDE_ASSETS` names that root for the crate's
//! tests.

#[path = "src/catalog_model.rs"]
mod catalog_model;

use catalog_model::{Member, ProfileData};
use serde::Deserialize;
use std::collections::BTreeMap;

const MODULES: &str = "data/catalogs/yara/modules.toml";
const LANGUAGE: &str = "data/catalogs/yara/language.toml";

#[derive(Deserialize)]
struct ModulesMeta {
    /// YARA-X's default modules, less the excluded ones.
    modules: Vec<String>,
}

/// `modules.toml`.
#[derive(Deserialize)]
struct ModulesFile {
    meta: ModulesMeta,
    /// Module name to why opentide refuses it.
    unsupported: BTreeMap<String, String>,
    member: Vec<Member>,
}

/// `language.toml`.
#[derive(Deserialize)]
struct LanguageFile {
    keywords: Vec<String>,
    profile: BTreeMap<String, ProfileData>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let datasets = opentide_dataset::build::Datasets::for_crate("data/catalogs")?;
    datasets.text_from_sources()?;

    let read = |rel: &str| {
        std::fs::read_to_string(datasets.root().join(rel))
            .map_err(|error| format!("{rel}: {error}"))
    };
    let modules: ModulesFile =
        toml::from_str(&read(MODULES)?).map_err(|error| format!("{MODULES}: {error}"))?;
    let language: LanguageFile =
        toml::from_str(&read(LANGUAGE)?).map_err(|error| format!("{LANGUAGE}: {error}"))?;
    datasets.value(
        "yara-catalog",
        &[MODULES, LANGUAGE],
        &(
            modules.meta.modules,
            modules.unsupported,
            modules.member,
            language.keywords,
            language.profile,
        ),
    )?;
    Ok(())
}
