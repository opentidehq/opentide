//! The vocabularies opentide ships (`src/opentide/data/vocabulary`), compiled
//! in and each parsed on first use.

use std::sync::{Arc, OnceLock};

use super::{Descriptions, VocabError, Vocabulary};

/// Every bundled vocabulary: its field and its document **without the entries' descriptions**, which
/// are most of a vocabulary's text and which a validation never reads (#1071). Each is decoded on
/// first use; [`DESCRIPTIONS`] holds the descriptions, decoded when one is asked for (#1743).
pub const FILES: &[(&str, opentide_dataset::TextFn)] = &[
    ("actors", || {
        opentide_dataset::text_blob!("vocab/lean/actors")
    }),
    ("alert_severity", || {
        opentide_dataset::text_blob!("vocab/lean/alert_severity")
    }),
    ("att&ck.groups", || {
        opentide_dataset::text_blob!("vocab/lean/att&ck.groups")
    }),
    ("att&ck", || {
        opentide_dataset::text_blob!("vocab/lean/att&ck")
    }),
    ("chaining_relations", || {
        opentide_dataset::text_blob!("vocab/lean/chaining_relations")
    }),
    ("collection", || {
        opentide_dataset::text_blob!("vocab/lean/collection")
    }),
    ("criticality", || {
        opentide_dataset::text_blob!("vocab/lean/criticality")
    }),
    ("datasources", || {
        opentide_dataset::text_blob!("vocab/lean/datasources")
    }),
    ("detection.composition", || {
        opentide_dataset::text_blob!("vocab/lean/detection.composition")
    }),
    ("detection.methodology", || {
        opentide_dataset::text_blob!("vocab/lean/detection.methodology")
    }),
    ("detection.types", || {
        opentide_dataset::text_blob!("vocab/lean/detection.types")
    }),
    ("efforts", || {
        opentide_dataset::text_blob!("vocab/lean/efforts")
    }),
    ("feasibility", || {
        opentide_dataset::text_blob!("vocab/lean/feasibility")
    }),
    ("impact", || {
        opentide_dataset::text_blob!("vocab/lean/impact")
    }),
    ("killchain", || {
        opentide_dataset::text_blob!("vocab/lean/killchain")
    }),
    ("level", || opentide_dataset::text_blob!("vocab/lean/level")),
    ("leverage", || {
        opentide_dataset::text_blob!("vocab/lean/leverage")
    }),
    ("maturity", || {
        opentide_dataset::text_blob!("vocab/lean/maturity")
    }),
    ("mitigations", || {
        opentide_dataset::text_blob!("vocab/lean/mitigations")
    }),
    ("objectives", || {
        opentide_dataset::text_blob!("vocab/lean/objectives")
    }),
    ("pap", || opentide_dataset::text_blob!("vocab/lean/pap")),
    ("resources", || {
        opentide_dataset::text_blob!("vocab/lean/resources")
    }),
    ("rsit", || opentide_dataset::text_blob!("vocab/lean/rsit")),
    ("scheduling", || {
        opentide_dataset::text_blob!("vocab/lean/scheduling")
    }),
    ("sectors", || {
        opentide_dataset::text_blob!("vocab/lean/sectors")
    }),
    ("severity", || {
        opentide_dataset::text_blob!("vocab/lean/severity")
    }),
    ("signal.entities", || {
        opentide_dataset::text_blob!("vocab/lean/signal.entities")
    }),
    ("sophistication", || {
        opentide_dataset::text_blob!("vocab/lean/sophistication")
    }),
    ("surface", || {
        opentide_dataset::text_blob!("vocab/lean/surface")
    }),
    ("tier", || opentide_dataset::text_blob!("vocab/lean/tier")),
    ("tlp", || opentide_dataset::text_blob!("vocab/lean/tlp")),
    ("viability", || {
        opentide_dataset::text_blob!("vocab/lean/viability")
    }),
    ("violation", || {
        opentide_dataset::text_blob!("vocab/lean/violation")
    }),
];

/// The descriptions of each bundled vocabulary's entries, in [`FILES`]' order: one line a
/// `[[keys]]` entry, the entry's `description = "..."` line as the document wrote it, or an empty
/// line for an entry without one.
pub const DESCRIPTIONS: &[(&str, opentide_dataset::TextFn)] = &[
    ("actors", || {
        opentide_dataset::text_blob!("vocab/descriptions/actors")
    }),
    ("alert_severity", || {
        opentide_dataset::text_blob!("vocab/descriptions/alert_severity")
    }),
    ("att&ck.groups", || {
        opentide_dataset::text_blob!("vocab/descriptions/att&ck.groups")
    }),
    ("att&ck", || {
        opentide_dataset::text_blob!("vocab/descriptions/att&ck")
    }),
    ("chaining_relations", || {
        opentide_dataset::text_blob!("vocab/descriptions/chaining_relations")
    }),
    ("collection", || {
        opentide_dataset::text_blob!("vocab/descriptions/collection")
    }),
    ("criticality", || {
        opentide_dataset::text_blob!("vocab/descriptions/criticality")
    }),
    ("datasources", || {
        opentide_dataset::text_blob!("vocab/descriptions/datasources")
    }),
    ("detection.composition", || {
        opentide_dataset::text_blob!("vocab/descriptions/detection.composition")
    }),
    ("detection.methodology", || {
        opentide_dataset::text_blob!("vocab/descriptions/detection.methodology")
    }),
    ("detection.types", || {
        opentide_dataset::text_blob!("vocab/descriptions/detection.types")
    }),
    ("efforts", || {
        opentide_dataset::text_blob!("vocab/descriptions/efforts")
    }),
    ("feasibility", || {
        opentide_dataset::text_blob!("vocab/descriptions/feasibility")
    }),
    ("impact", || {
        opentide_dataset::text_blob!("vocab/descriptions/impact")
    }),
    ("killchain", || {
        opentide_dataset::text_blob!("vocab/descriptions/killchain")
    }),
    ("level", || {
        opentide_dataset::text_blob!("vocab/descriptions/level")
    }),
    ("leverage", || {
        opentide_dataset::text_blob!("vocab/descriptions/leverage")
    }),
    ("maturity", || {
        opentide_dataset::text_blob!("vocab/descriptions/maturity")
    }),
    ("mitigations", || {
        opentide_dataset::text_blob!("vocab/descriptions/mitigations")
    }),
    ("objectives", || {
        opentide_dataset::text_blob!("vocab/descriptions/objectives")
    }),
    ("pap", || {
        opentide_dataset::text_blob!("vocab/descriptions/pap")
    }),
    ("resources", || {
        opentide_dataset::text_blob!("vocab/descriptions/resources")
    }),
    ("rsit", || {
        opentide_dataset::text_blob!("vocab/descriptions/rsit")
    }),
    ("scheduling", || {
        opentide_dataset::text_blob!("vocab/descriptions/scheduling")
    }),
    ("sectors", || {
        opentide_dataset::text_blob!("vocab/descriptions/sectors")
    }),
    ("severity", || {
        opentide_dataset::text_blob!("vocab/descriptions/severity")
    }),
    ("signal.entities", || {
        opentide_dataset::text_blob!("vocab/descriptions/signal.entities")
    }),
    ("sophistication", || {
        opentide_dataset::text_blob!("vocab/descriptions/sophistication")
    }),
    ("surface", || {
        opentide_dataset::text_blob!("vocab/descriptions/surface")
    }),
    ("tier", || {
        opentide_dataset::text_blob!("vocab/descriptions/tier")
    }),
    ("tlp", || {
        opentide_dataset::text_blob!("vocab/descriptions/tlp")
    }),
    ("viability", || {
        opentide_dataset::text_blob!("vocab/descriptions/viability")
    }),
    ("violation", || {
        opentide_dataset::text_blob!("vocab/descriptions/violation")
    }),
];

type Slot = OnceLock<Result<Arc<Vocabulary>, VocabError>>;

/// The descriptions of each bundled vocabulary, in [`FILES`]' order, each decoded when one of its
/// entries is asked for its description.
fn descriptions() -> &'static [Descriptions] {
    static DESCRIPTIONS_OF: OnceLock<Vec<Descriptions>> = OnceLock::new();
    DESCRIPTIONS_OF.get_or_init(|| {
        DESCRIPTIONS
            .iter()
            .map(|(_, text)| Descriptions::new(*text))
            .collect()
    })
}

fn slots() -> &'static [Slot] {
    static SLOTS: OnceLock<Vec<Slot>> = OnceLock::new();
    SLOTS.get_or_init(|| FILES.iter().map(|_| OnceLock::new()).collect())
}

/// The bundled vocabulary `field`, parsed on first use; `None` when opentide
/// ships no such vocabulary.
pub fn load(field: &str) -> Option<Result<Arc<Vocabulary>, VocabError>> {
    let index = FILES.iter().position(|(name, _)| *name == field)?;
    let (name, text) = FILES[index];
    let text = text();
    Some(
        slots()[index]
            .get_or_init(|| {
                Vocabulary::from_bundled_file(
                    &format!("{name}{}", super::SUFFIX),
                    text,
                    &descriptions()[index],
                )
                .map(Arc::new)
            })
            .clone(),
    )
}

/// The bundled vocabulary `field`, if opentide ships it and it reads.
pub fn get(field: &str) -> Option<Arc<Vocabulary>> {
    load(field).and_then(Result::ok)
}

/// The fields of the bundled vocabularies, in file name order.
pub fn fields() -> impl Iterator<Item = &'static str> {
    FILES.iter().map(|(field, _)| *field)
}
