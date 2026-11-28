//! Compiles the datasets of the command line in (#1743), each a zstd blob
//! decoded once on first use:
//!
//! - every `opentide_dataset::text!("<path>")` in `src/` (the MCP host templates
//!   of `setup`, its skills, its entrypoint templates);
//! - the `opentide explain` pages, one blob per Markdown file of
//!   `src/opentide/data/diagnostics/`, listed in `$OUT_DIR/explain_pages.rs` as
//!   `PAGES: &[(&str, opentide_dataset::TextFn)]` (code, Markdown), sorted by code.
//!   The pages are the package's data, shipped in the wheel beside the compiled
//!   command line.
//!
//! The files are read from the workspace root in a checkout, or else from the
//! `assets/` copy that `scripts/engine/release.py vendor` puts inside the
//! published crate (`[package.metadata.opentide] assets`). The checkout wins,
//! so a copy left behind never shadows the real files. `OPENTIDE_ASSETS` names
//! that root for the crate's tests.

use std::fmt::Write as _;
use std::path::PathBuf;

const PAGES: &str = "src/opentide/data/diagnostics";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let datasets = opentide_dataset::build::Datasets::for_crate(PAGES)?;
    datasets.text_from_sources()?;

    let pages = datasets.root().join(PAGES);
    // A folder that cannot be read is a build error: without its pages,
    // `explain` would list no code and SARIF would carry no rules.
    let mut codes: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&pages).map_err(|error| {
        format!(
            "the explain pages are read from {}: {error}",
            pages.display()
        )
    })? {
        let path: PathBuf = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("md")
            && let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
        {
            codes.push(stem.to_owned());
        }
    }
    if codes.is_empty() {
        return Err(format!("no explain page (*.md) in {}", pages.display()).into());
    }
    codes.sort();
    let mut out = String::from("/// The explain pages: (code, Markdown), sorted by code.\n");
    out.push_str("pub const PAGES: &[(&str, opentide_dataset::TextFn)] = &[\n");
    for code in &codes {
        let rel = format!("{PAGES}/{code}.md");
        datasets.text(&rel)?;
        writeln!(out, "    ({code:?}, || opentide_dataset::text!({rel:?})),")?;
    }
    out.push_str("];\n");
    let target = PathBuf::from(std::env::var("OUT_DIR")?).join("explain_pages.rs");
    std::fs::write(target, out)?;
    println!("cargo:rerun-if-changed={}", pages.display());
    Ok(())
}
