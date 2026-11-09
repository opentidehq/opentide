//! The vocabularies opentide ships (`src/opentide/data/vocabulary`), compiled
//! in and each parsed on first use.

use std::sync::{Arc, OnceLock};

use super::{VocabError, Vocabulary};

/// Every bundled vocabulary: its field and its document.
pub const FILES: &[(&str, &str)] = &[
    (
        "actors",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/actors.vocab.toml"
        )),
    ),
    (
        "alert_severity",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/alert_severity.vocab.toml"
        )),
    ),
    (
        "att&ck.groups",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/att&ck.groups.vocab.toml"
        )),
    ),
    (
        "att&ck",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/att&ck.vocab.toml"
        )),
    ),
    (
        "chaining_relations",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/chaining_relations.vocab.toml"
        )),
    ),
    (
        "collection",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/collection.vocab.toml"
        )),
    ),
    (
        "criticality",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/criticality.vocab.toml"
        )),
    ),
    (
        "datasources",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/datasources.vocab.toml"
        )),
    ),
    (
        "detection.composition",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/detection.composition.vocab.toml"
        )),
    ),
    (
        "detection.methodology",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/detection.methodology.vocab.toml"
        )),
    ),
    (
        "detection.types",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/detection.types.vocab.toml"
        )),
    ),
    (
        "efforts",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/efforts.vocab.toml"
        )),
    ),
    (
        "feasibility",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/feasibility.vocab.toml"
        )),
    ),
    (
        "impact",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/impact.vocab.toml"
        )),
    ),
    (
        "killchain",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/killchain.vocab.toml"
        )),
    ),
    (
        "level",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/level.vocab.toml"
        )),
    ),
    (
        "leverage",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/leverage.vocab.toml"
        )),
    ),
    (
        "malapi",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/malapi.vocab.toml"
        )),
    ),
    (
        "maturity",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/maturity.vocab.toml"
        )),
    ),
    (
        "mitigations",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/mitigations.vocab.toml"
        )),
    ),
    (
        "objectives",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/objectives.vocab.toml"
        )),
    ),
    (
        "pap",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/pap.vocab.toml"
        )),
    ),
    (
        "resources",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/resources.vocab.toml"
        )),
    ),
    (
        "rsit",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/rsit.vocab.toml"
        )),
    ),
    (
        "scheduling",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/scheduling.vocab.toml"
        )),
    ),
    (
        "sectors",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/sectors.vocab.toml"
        )),
    ),
    (
        "severity",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/severity.vocab.toml"
        )),
    ),
    (
        "signal.entities",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/signal.entities.vocab.toml"
        )),
    ),
    (
        "sophistication",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/sophistication.vocab.toml"
        )),
    ),
    (
        "stakeholders",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/stakeholders.vocab.toml"
        )),
    ),
    (
        "surface",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/surface.vocab.toml"
        )),
    ),
    (
        "tier",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/tier.vocab.toml"
        )),
    ),
    (
        "tlp",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/tlp.vocab.toml"
        )),
    ),
    (
        "viability",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/viability.vocab.toml"
        )),
    ),
    (
        "violation",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/vocabulary/violation.vocab.toml"
        )),
    ),
];

type Slot = OnceLock<Result<Arc<Vocabulary>, VocabError>>;

fn slots() -> &'static [Slot] {
    static SLOTS: OnceLock<Vec<Slot>> = OnceLock::new();
    SLOTS.get_or_init(|| FILES.iter().map(|_| OnceLock::new()).collect())
}

/// The bundled vocabulary `field`, parsed on first use; `None` when opentide
/// ships no such vocabulary.
pub fn load(field: &str) -> Option<Result<Arc<Vocabulary>, VocabError>> {
    let index = FILES.iter().position(|(name, _)| *name == field)?;
    let (name, text) = FILES[index];
    Some(
        slots()[index]
            .get_or_init(|| {
                Vocabulary::from_file(&format!("{name}{}", super::SUFFIX), text).map(Arc::new)
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
