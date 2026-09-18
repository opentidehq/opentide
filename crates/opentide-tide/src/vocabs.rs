//! All Tide vocabulary TOML files, compiled in via `include_str!`.

use std::collections::BTreeMap;
use std::sync::OnceLock;

const VOCAB_ACTORS: &str = include_str!("../../../catalogs/tide/vocabs/actors.vocab.toml");
const VOCAB_ALERT_SEVERITY: &str =
    include_str!("../../../catalogs/tide/vocabs/alert_severity.vocab.toml");
const VOCAB_ATT_AND_CK_GROUPS: &str =
    include_str!("../../../catalogs/tide/vocabs/att&ck.groups.vocab.toml");
const VOCAB_ATT_AND_CK: &str = include_str!("../../../catalogs/tide/vocabs/att&ck.vocab.toml");
const VOCAB_CHAINING_RELATIONS: &str =
    include_str!("../../../catalogs/tide/vocabs/chaining_relations.vocab.toml");
const VOCAB_COLLECTION: &str = include_str!("../../../catalogs/tide/vocabs/collection.vocab.toml");
const VOCAB_CRITICALITY: &str =
    include_str!("../../../catalogs/tide/vocabs/criticality.vocab.toml");
const VOCAB_DATASOURCES: &str =
    include_str!("../../../catalogs/tide/vocabs/datasources.vocab.toml");
const VOCAB_DETECTION_COMPOSITION: &str =
    include_str!("../../../catalogs/tide/vocabs/detection.composition.vocab.toml");
const VOCAB_DETECTION_METHODOLOGY: &str =
    include_str!("../../../catalogs/tide/vocabs/detection.methodology.vocab.toml");
const VOCAB_DETECTION_TYPES: &str =
    include_str!("../../../catalogs/tide/vocabs/detection.types.vocab.toml");
const VOCAB_EFFORTS: &str = include_str!("../../../catalogs/tide/vocabs/efforts.vocab.toml");
const VOCAB_FEASIBILITY: &str =
    include_str!("../../../catalogs/tide/vocabs/feasibility.vocab.toml");
const VOCAB_IMPACT: &str = include_str!("../../../catalogs/tide/vocabs/impact.vocab.toml");
const VOCAB_KILLCHAIN: &str = include_str!("../../../catalogs/tide/vocabs/killchain.vocab.toml");
const VOCAB_LEVEL: &str = include_str!("../../../catalogs/tide/vocabs/level.vocab.toml");
const VOCAB_LEVERAGE: &str = include_str!("../../../catalogs/tide/vocabs/leverage.vocab.toml");
const VOCAB_MALAPI: &str = include_str!("../../../catalogs/tide/vocabs/malapi.vocab.toml");
const VOCAB_MATURITY: &str = include_str!("../../../catalogs/tide/vocabs/maturity.vocab.toml");
const VOCAB_MITIGATIONS: &str =
    include_str!("../../../catalogs/tide/vocabs/mitigations.vocab.toml");
const VOCAB_OBJECTIVES: &str = include_str!("../../../catalogs/tide/vocabs/objectives.vocab.toml");
const VOCAB_PAP: &str = include_str!("../../../catalogs/tide/vocabs/pap.vocab.toml");
const VOCAB_RESOURCES: &str = include_str!("../../../catalogs/tide/vocabs/resources.vocab.toml");
const VOCAB_RESPONDERS: &str = include_str!("../../../catalogs/tide/vocabs/responders.vocab.toml");
const VOCAB_RSIT: &str = include_str!("../../../catalogs/tide/vocabs/rsit.vocab.toml");
const VOCAB_SCHEDULING: &str = include_str!("../../../catalogs/tide/vocabs/scheduling.vocab.toml");
const VOCAB_SECTORS: &str = include_str!("../../../catalogs/tide/vocabs/sectors.vocab.toml");
const VOCAB_SEVERITY: &str = include_str!("../../../catalogs/tide/vocabs/severity.vocab.toml");
const VOCAB_SIGNAL_ENTITIES: &str =
    include_str!("../../../catalogs/tide/vocabs/signal.entities.vocab.toml");
const VOCAB_SOPHISTICATION: &str =
    include_str!("../../../catalogs/tide/vocabs/sophistication.vocab.toml");
const VOCAB_STAKEHOLDERS: &str =
    include_str!("../../../catalogs/tide/vocabs/stakeholders.vocab.toml");
const VOCAB_SURFACE: &str = include_str!("../../../catalogs/tide/vocabs/surface.vocab.toml");
const VOCAB_TIER: &str = include_str!("../../../catalogs/tide/vocabs/tier.vocab.toml");
const VOCAB_TLP: &str = include_str!("../../../catalogs/tide/vocabs/tlp.vocab.toml");
const VOCAB_VIABILITY: &str = include_str!("../../../catalogs/tide/vocabs/viability.vocab.toml");
const VOCAB_VIOLATION: &str = include_str!("../../../catalogs/tide/vocabs/violation.vocab.toml");

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
    VOCAB_RESPONDERS,
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

    pub fn suggest(&self, value: &str) -> Option<String> {
        let needle = value.to_ascii_lowercase();
        self.keys
            .iter()
            .map(|k| {
                let d = levenshtein(&k.name.to_ascii_lowercase(), &needle);
                (k.name.clone(), d)
            })
            .filter(|(_, d)| *d <= 4)
            .min_by_key(|(_, d)| *d)
            .map(|(n, _)| n)
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

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

fn parse_vocab(toml_src: &str) -> Vocab {
    let v: toml::Value = toml::from_str(toml_src).expect("vocab toml");
    let field = v
        .get("field")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let title = v.get("name").and_then(|v| v.as_str()).map(str::to_string);
    let token_field = v.get("key").and_then(|v| v.as_str()).unwrap_or("name");
    let keys = v
        .get("keys")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|k| {
            let token = k
                .get(token_field)
                .and_then(|x| x.as_str())
                .or_else(|| k.get("name").and_then(|x| x.as_str()))
                .or_else(|| k.get("id").and_then(|x| x.as_str()))?;
            let pretty = k.get("name").and_then(|x| x.as_str()).map(str::to_string);
            Some(VocabKey {
                name: token.to_string(),
                title: pretty.filter(|p| p != token),
                description: k
                    .get("description")
                    .and_then(|d| d.as_str())
                    .map(str::to_string),
            })
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
}
