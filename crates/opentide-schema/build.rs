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

// What an offer is worked out from (`src/vocab/offer.rs`), compiled into the build script too: the
// vocabulary documents, their pins, the Markdown clean-up and the offer itself. The crate's other
// modules reach these through `super::`, which is this root.
#[path = "src/generate/annotate.rs"]
#[expect(
    dead_code,
    reason = "the build script reads only the Markdown clean-up"
)]
mod annotate;
#[path = "src/vocab/document.rs"]
#[expect(dead_code, reason = "the build script reads documents from text only")]
mod document;
#[path = "src/vocab/error.rs"]
mod error;
#[path = "src/generate/json.rs"]
#[expect(
    dead_code,
    reason = "the build script reads only the Markdown clean-up"
)]
mod json;
#[path = "src/vocab/offer.rs"]
mod offer;
#[path = "src/vocab/version.rs"]
#[expect(dead_code, reason = "the build script reads only the pins' syntax")]
mod version;

use annotate::{first_sentence, plain_text};
use document::{Entry, KeyKind, Vocabulary};
use error::VocabError;
use version::{Version, VocabRef};

/// The object families whose vocabularies are the workspace's own (`vocab::OBJECT_TYPES`).
const OBJECT_TYPES: [&str; 3] = ["threat", "objective", "rule"];

const VOCABULARIES: &str = "src/opentide/data/vocabulary";
const SUFFIX: &str = ".vocab.toml";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let datasets = opentide_dataset::build::Datasets::for_crate(VOCABULARIES)?;
    datasets.text_from_sources()?;

    let mut offers: Vec<(String, String, String)> = Vec::new();
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
        offers.push((field.to_owned(), source, text));
    }
    write_offers(&datasets, &offers)
}

/// The offers of the bundled vocabularies that the schemas and the field catalog ask for, as the
/// reference a field names (`field` or `field::M.m`) and whether it asks for scoped values: a
/// reference a field asks for that is not here is worked out when it is asked for, and the crate's
/// test `the_build_makes_the_offers_the_catalog_asks_for` fails until it is added.
const OFFERED: &[(&str, bool)] = &[
    ("actors::1.1", true),
    ("alert_severity::1.0", false),
    ("att&ck::1.2", false),
    ("chaining_relations::1.0", false),
    ("criticality::1.0", false),
    ("detection.composition::1.0", false),
    ("detection.methodology::1.0", false),
    ("detection.types::1.0", false),
    ("impact::1.0", false),
    ("killchain::1.0", false),
    ("leverage::1.0", false),
    ("severity::1.0", false),
    ("signal.entities::1.0", true),
    ("surface::1.0", true),
    ("tlp::1.0", false),
    ("viability::1.0", false),
];

/// The offer of each of [`OFFERED`]: a blob for each, and `vocab_offers.rs`, the table of their
/// decoders (`src/vocab/bundled_offers.rs`).
fn write_offers(
    datasets: &opentide_dataset::build::Datasets,
    vocabularies: &[(String, String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut table = String::from("pub(super) const OFFERS: &[(&str, bool, Load)] = &[\n");
    for (reference, scoped) in OFFERED {
        let vocab: VocabRef = reference
            .parse()
            .map_err(|error| format!("{reference}: {error}"))?;
        let (_, source, text) = vocabularies
            .iter()
            .find(|(field, _, _)| *field == vocab.field)
            .ok_or_else(|| format!("{reference}: no such bundled vocabulary"))?;
        let vocabulary = Vocabulary::from_file(&format!("{}.vocab.toml", vocab.field), text)
            .map_err(|error| format!("{reference}: {error}"))?;
        let offer = offer::offer_of(
            &vocabulary,
            &vocab,
            offer::VocabOptions {
                scoped: *scoped,
                no_wrap: false,
            },
        );
        // A file name has no `::`: a colon is not a file name's on Windows.
        let name = format!(
            "vocab/offer/{}.{}",
            reference.replace("::", "@"),
            if *scoped { "scoped" } else { "plain" }
        );
        datasets.value(&name, &[source], &offer)?;
        table.push_str(&format!(
            "    ({reference:?}, {scoped}, || opentide_dataset::value!(Offer, {name:?})),\n"
        ));
    }
    table.push_str("];\n");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").ok_or("OUT_DIR is not set")?);
    std::fs::write(out.join("vocab_offers.rs"), table)?;
    Ok(())
}
