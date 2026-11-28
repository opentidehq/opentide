//! Compresses the datasets this crate compiles in (#1743): every
//! `opentide_dataset::text!("<path>")` in `src/` names a file of the shared catalogs and highlight data,
//! which becomes a zstd blob in `OUT_DIR`, decoded once on first use.
//!
//! The files are read from the workspace root in a checkout, or else from the
//! `assets/` copy that `scripts/engine/release.py vendor` puts inside a
//! published crate; the checkout wins, so a copy left behind never shadows the
//! real files. `OPENTIDE_ASSETS` names that root for the crate's tests.

fn main() -> Result<(), opentide_dataset::build::BuildError> {
    opentide_dataset::build::Datasets::for_crate("data/catalogs")?.text_from_sources()?;
    Ok(())
}
