//! Compiles in the `opentide explain` pages: one `include_str!` per Markdown
//! file of `src/opentide/data/diagnostics/`, written to
//! `$OUT_DIR/explain_pages.rs` as `PAGES: &[(&str, &str)]` (code, Markdown),
//! sorted by code. The pages are the package's data; the Python CLI reads
//! the same files.
//!
//! Also points `include_str!` at that data (`OPENTIDE_ASSETS`, the MCP host
//! templates of `setup`): the workspace root in a checkout, or else the
//! `assets/` copy that `scripts/engine/release.py vendor` puts inside the
//! published crate (`[package.metadata.opentide] assets`), as opentide-schema
//! does. The checkout wins, so a copy left behind never shadows the real files.

use std::fmt::Write as _;
use std::path::PathBuf;

#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a build script: cargo sets its variables, and a page that cannot be listed fails the build"
)]
fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest.join("../..");
    // A packaged crate builds under target/package/ or the registry, where ../.. has no
    // src/opentide/data/.
    let root = if workspace.join("src/opentide/data/diagnostics").is_dir() {
        workspace
    } else {
        manifest.join("assets")
    };
    println!("cargo:rustc-env=OPENTIDE_ASSETS={}", root.display());
    let pages = root.join("src/opentide/data/diagnostics");
    let mut found: Vec<(String, PathBuf)> = Vec::new();
    // A folder that cannot be read is a build error: without its pages,
    // `explain` would list no code and SARIF would carry no rules.
    let entries = std::fs::read_dir(&pages).unwrap_or_else(|error| {
        panic!(
            "the explain pages are read from {}: {error}",
            pages.display()
        )
    });
    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("md")
            && let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
        {
            found.push((stem.to_owned(), path.canonicalize().unwrap()));
        }
    }
    assert!(
        !found.is_empty(),
        "no explain page (*.md) in {}",
        pages.display()
    );
    found.sort();
    let mut out = String::from("/// The explain pages: (code, Markdown), sorted by code.\n");
    out.push_str("pub const PAGES: &[(&str, &str)] = &[\n");
    for (code, path) in &found {
        writeln!(
            out,
            "    ({code:?}, include_str!({:?})),",
            path.display().to_string()
        )
        .unwrap();
    }
    out.push_str("];\n");
    let target = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("explain_pages.rs");
    std::fs::write(target, out).unwrap();
    println!("cargo:rerun-if-changed={}", pages.display());
    println!("cargo:rerun-if-changed=build.rs");
}
