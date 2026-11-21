//! Compresses the datasets this crate compiles in (#1743).
//!
//! - Every `opentide_dataset::text!` of a path under the package data (`src/opentide/data`) in
//!   `src/` becomes a zstd blob in `OUT_DIR`, decoded once on first use.
//! - Each bundled vocabulary (`src/opentide/data/vocabulary/*.vocab.toml`) is stored as two blobs,
//!   `vocab/lean/<field>` (the document without its entries' descriptions) and
//!   `vocab/descriptions/<field>` (the descriptions, a line an entry): a validation reads keys and
//!   names, so it decodes the first, a fifth of the text, and the descriptions only when one is
//!   asked for (`src/vocab/split.rs`).
//!
//! The files are read from the workspace root in a checkout, or else from the `assets/` copy that
//! `scripts/engine/release.py vendor` puts inside a published crate; the checkout wins, so a copy
//! left behind never shadows the real files. `OPENTIDE_ASSETS` names that root for the tests.

#[path = "src/vocab/split.rs"]
mod split;

const VOCABULARIES: &str = "src/opentide/data/vocabulary";
const SUFFIX: &str = ".vocab.toml";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let datasets = opentide_dataset::build::Datasets::for_crate(VOCABULARIES)?;
    datasets.text_from_sources()?;

    let directory = datasets.root().join(VOCABULARIES);
    println!("cargo:rerun-if-changed={}", directory.display());
    for entry in
        std::fs::read_dir(&directory).map_err(|e| format!("{}: {e}", directory.display()))?
    {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(field) = name.strip_suffix(SUFFIX) else {
            continue;
        };
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let (lean, descriptions) = split::split(&text);
        let source = format!("{VOCABULARIES}/{name}");
        datasets.text_named(&format!("vocab/lean/{field}"), &[&source], &lean)?;
        datasets.text_named(
            &format!("vocab/descriptions/{field}"),
            &[&source],
            &descriptions,
        )?;
    }
    Ok(())
}
