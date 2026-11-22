//! Compiles the crate's datasets in (#1743).
//!
//! - Every `opentide_dataset::text!("<path>")` in `src/` becomes a zstd blob in
//!   `OUT_DIR`, decoded once on first use.
//! - The Tide vocabularies (`src/opentide/data/vocabulary/*.vocab.toml`, the
//!   editor's hover and completion data) are parsed here, once, into
//!   [`vocab_model::Vocab`]s and stored as one pre-parsed blob, `vocabularies`:
//!   the editor used to parse all thirty-three files, ATT&CK's included, the first
//!   time it needed one.
//!
//! The files are read from the workspace root in a checkout, or else from the
//! `assets/` copy that `scripts/engine/release.py vendor` puts inside a
//! published crate; the checkout wins. `OPENTIDE_ASSETS` names that root for
//! the crate's tests.

#[path = "src/vocab_model.rs"]
mod vocab_model;

const VOCABULARIES: &str = "src/opentide/data/vocabulary";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let datasets = opentide_dataset::build::Datasets::for_crate("data/catalogs")?;
    datasets.text_from_sources()?;

    let directory = datasets.root().join(VOCABULARIES);
    println!("cargo:rerun-if-changed={}", directory.display());
    let mut files: Vec<_> = std::fs::read_dir(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".vocab.toml"))
        })
        .collect();
    files.sort();
    let mut vocabularies = Vec::new();
    let mut sources = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let vocab = vocab_model::parse_vocab(&text)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if !vocab.field.is_empty() {
            vocabularies.push(vocab);
        }
        if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            sources.push(format!("{VOCABULARIES}/{name}"));
        }
    }
    let sources: Vec<&str> = sources.iter().map(String::as_str).collect();
    datasets.value("vocabularies", &sources, &vocabularies)?;
    Ok(())
}
