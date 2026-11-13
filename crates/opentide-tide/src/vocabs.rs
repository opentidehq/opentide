//! The Tide vocabularies the editor reads, compiled in via `include_str!`.
//!
//! They are the one bundled set, `src/opentide/data/vocabulary`, which
//! opentide-schema compiles in for `validate` and the upstream sync
//! (`.github/workflows/vocab-upstream.yml`) writes: a second copy under
//! `data/catalogs/tide/vocabs` had drifted by 538 lines of `actors` alone
//! before UC-1.6 ([#812](https://github.com/opentidehq/opentide/issues/812)).

use std::collections::BTreeMap;
use std::sync::OnceLock;

const VOCAB_ACTORS: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/actors.vocab.toml"
));
const VOCAB_ALERT_SEVERITY: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/alert_severity.vocab.toml"
));
const VOCAB_ATT_AND_CK_GROUPS: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/att&ck.groups.vocab.toml"
));
const VOCAB_ATT_AND_CK: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/att&ck.vocab.toml"
));
const VOCAB_CHAINING_RELATIONS: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/chaining_relations.vocab.toml"
));
const VOCAB_COLLECTION: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/collection.vocab.toml"
));
const VOCAB_CRITICALITY: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/criticality.vocab.toml"
));
const VOCAB_DATASOURCES: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/datasources.vocab.toml"
));
const VOCAB_DETECTION_COMPOSITION: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/detection.composition.vocab.toml"
));
const VOCAB_DETECTION_METHODOLOGY: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/detection.methodology.vocab.toml"
));
const VOCAB_DETECTION_TYPES: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/detection.types.vocab.toml"
));
const VOCAB_EFFORTS: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/efforts.vocab.toml"
));
const VOCAB_FEASIBILITY: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/feasibility.vocab.toml"
));
const VOCAB_IMPACT: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/impact.vocab.toml"
));
const VOCAB_KILLCHAIN: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/killchain.vocab.toml"
));
const VOCAB_LEVEL: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/level.vocab.toml"
));
const VOCAB_LEVERAGE: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/leverage.vocab.toml"
));
const VOCAB_MALAPI: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/malapi.vocab.toml"
));
const VOCAB_MATURITY: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/maturity.vocab.toml"
));
const VOCAB_MITIGATIONS: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/mitigations.vocab.toml"
));
const VOCAB_OBJECTIVES: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/objectives.vocab.toml"
));
const VOCAB_PAP: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/pap.vocab.toml"
));
const VOCAB_RESOURCES: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/resources.vocab.toml"
));
const VOCAB_RSIT: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/rsit.vocab.toml"
));
const VOCAB_SCHEDULING: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/scheduling.vocab.toml"
));
const VOCAB_SECTORS: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/sectors.vocab.toml"
));
const VOCAB_SEVERITY: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/severity.vocab.toml"
));
const VOCAB_SIGNAL_ENTITIES: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/signal.entities.vocab.toml"
));
const VOCAB_SOPHISTICATION: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/sophistication.vocab.toml"
));
const VOCAB_STAKEHOLDERS: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/stakeholders.vocab.toml"
));
const VOCAB_SURFACE: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/surface.vocab.toml"
));
const VOCAB_TIER: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/tier.vocab.toml"
));
const VOCAB_TLP: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/tlp.vocab.toml"
));
const VOCAB_VIABILITY: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/viability.vocab.toml"
));
const VOCAB_VIOLATION: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/violation.vocab.toml"
));

const ALL_VOCABS: &[&str] = &[
    VOCAB_ACTORS,
    VOCAB_ALERT_SEVERITY,
    VOCAB_ATT_AND_CK_GROUPS,
    VOCAB_ATT_AND_CK,
    VOCAB_CHAINING_RELATIONS,
    VOCAB_COLLECTION,
    VOCAB_CRITICALITY,
    VOCAB_DATASOURCES,
    VOCAB_DETECTION_COMPOSITION,
    VOCAB_DETECTION_METHODOLOGY,
    VOCAB_DETECTION_TYPES,
    VOCAB_EFFORTS,
    VOCAB_FEASIBILITY,
    VOCAB_IMPACT,
    VOCAB_KILLCHAIN,
    VOCAB_LEVEL,
    VOCAB_LEVERAGE,
    VOCAB_MALAPI,
    VOCAB_MATURITY,
    VOCAB_MITIGATIONS,
    VOCAB_OBJECTIVES,
    VOCAB_PAP,
    VOCAB_RESOURCES,
    VOCAB_RSIT,
    VOCAB_SCHEDULING,
    VOCAB_SECTORS,
    VOCAB_SEVERITY,
    VOCAB_SIGNAL_ENTITIES,
    VOCAB_SOPHISTICATION,
    VOCAB_STAKEHOLDERS,
    VOCAB_SURFACE,
    VOCAB_TIER,
    VOCAB_TLP,
    VOCAB_VIABILITY,
    VOCAB_VIOLATION,
];

#[derive(Debug, Clone)]
pub struct Vocab {
    pub field: String,
    pub title: Option<String>,
    pub keys: Vec<VocabKey>,
}

#[derive(Debug, Clone)]
pub struct VocabKey {
    /// Token written in YAML (`clear`, `T1059`, `G0006`, …).
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
}

impl Vocab {
    pub fn contains(&self, value: &str) -> bool {
        self.keys.iter().any(|k| k.name == value)
    }

    pub fn get(&self, value: &str) -> Option<&VocabKey> {
        self.keys.iter().find(|k| k.name == value)
    }

    /// The key `value` most likely means ([`opentide_core::suggest`]).
    pub fn suggest(&self, value: &str) -> Option<String> {
        opentide_core::suggest::closest(value, self.keys.iter().map(|k| k.name.as_str()))
            .map(str::to_string)
    }

    pub fn hover(&self, value: &str) -> Option<String> {
        self.get(value).map(|k| {
            let title = k.title.as_deref().unwrap_or(k.name.as_str());
            let mut md = format!("**{title}** (`{}` / `{}`)", k.name, self.field);
            if let Some(d) = &k.description {
                md.push_str("\n\n");
                md.push_str(d);
            }
            md
        })
    }
}

/// Stage ids a key belongs to: `"tide.vocab.stages"` is a string or an array of them.
fn key_stages(key: &toml::Value) -> Vec<String> {
    match key.get("tide.vocab.stages") {
        Some(toml::Value::String(stage)) => vec![stage.clone()],
        Some(toml::Value::Array(stages)) => stages
            .iter()
            .filter_map(|stage| stage.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

#[expect(
    clippy::expect_used,
    reason = "every caller passes a vocabulary compiled in with include_str! (ALL_VOCABS): a bad one fails the tests, never a user's document"
)]
fn parse_vocab(toml_src: &str) -> Vocab {
    let v: toml::Value = toml::from_str(toml_src).expect("vocab toml");
    let field = v
        .get("field")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let title = v.get("name").and_then(|v| v.as_str()).map(str::to_string);
    let token_field = v.get("key").and_then(|v| v.as_str()).unwrap_or("name");
    // A vocabulary with `[[stages]]` tables scopes its keys: the value written in YAML is
    // `<stage>::<key>` (`support::enabled`), because two stages may define the same key.
    let scoped = v
        .get("stages")
        .and_then(|v| v.as_array())
        .is_some_and(|stages| stages.iter().any(|stage| stage.is_table()));
    let keys = v
        .get("keys")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .flat_map(|k| {
            let token = k
                .get(token_field)
                .and_then(|x| x.as_str())
                .or_else(|| k.get("name").and_then(|x| x.as_str()))
                .or_else(|| k.get("id").and_then(|x| x.as_str()));
            let Some(token) = token else {
                return Vec::new();
            };
            let pretty = k.get("name").and_then(|x| x.as_str()).map(str::to_string);
            let description = k
                .get("description")
                .and_then(|d| d.as_str())
                .map(str::to_string);
            let stages = if scoped { key_stages(k) } else { Vec::new() };
            let tokens: Vec<String> = if stages.is_empty() {
                vec![token.to_string()]
            } else {
                stages
                    .iter()
                    .map(|stage| format!("{stage}::{token}"))
                    .collect()
            };
            tokens
                .into_iter()
                .map(|name| VocabKey {
                    title: pretty.clone().filter(|p| *p != name),
                    name,
                    description: description.clone(),
                })
                .collect()
        })
        .collect();
    Vocab { field, title, keys }
}

pub fn bundled_vocabs() -> &'static BTreeMap<String, Vocab> {
    static INDEX: OnceLock<BTreeMap<String, Vocab>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut m = BTreeMap::new();
        for src in ALL_VOCABS {
            let v = parse_vocab(src);
            if !v.field.is_empty() {
                m.insert(v.field.clone(), v);
            }
        }
        m
    })
}

pub fn vocab_for_field(field: &str) -> Option<&'static Vocab> {
    bundled_vocabs().get(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_all_vocab_files() {
        let v = bundled_vocabs();
        assert!(v.len() >= 35, "expected 36 vocabs, got {}", v.len());
        assert!(v.contains_key("tlp"));
        assert!(v.contains_key("att&ck"));
        assert!(v.contains_key("actors"));
        assert!(v.contains_key("scheduling"));
        assert!(v.contains_key("detection.types"));
        assert!(v.get("tlp").unwrap().contains("clear"));
        assert!(v.get("att&ck").unwrap().contains("T1059"));
    }

    #[test]
    fn staged_vocabularies_are_written_with_their_stage() {
        let chaining = bundled_vocabs().get("chaining_relations").unwrap();
        assert!(chaining.contains("sequence::preceeds"));
        assert!(chaining.contains("support::enabled"));
        assert!(!chaining.contains("preceeds"));
    }
}
