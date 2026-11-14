//! Vocabulary entries as pages show them (`documentation/vocabulary.py`
//! `enrich`, `generation/framework.py` `get_vocab_entry`).

use opentide_schema::vocab::{Entry, Vocabularies};

/// An entry's label, description and link, the key itself when the
/// vocabulary has no entry for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Enriched {
    /// The value looked up.
    pub key: String,
    /// The entry's name, else the key.
    pub label: String,
    /// The description, newlines kept.
    pub description: String,
    /// The link.
    pub link: String,
    /// The entry's `id`, when it has one (TLP: `TLP:CLEAR`).
    pub id: String,
    /// The entry's stages (`tide.vocab.stages`).
    pub stages: Vec<String>,
    /// Whether the vocabulary has the entry.
    pub found: bool,
}

/// How a chaining relation is drawn (`ChainingRelation`). The vocabulary
/// pairs each relation with its inverse in one family (`preceeds` /
/// `succeeds` in `sequence`): the `from` side points away from the threat
/// that declares it, the `to` side towards it. A diagram draws every pair the
/// `from` way, so the arrows of a chain all read one way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainingRelation {
    /// The relation's name, else its key.
    pub label: String,
    /// `sequence`, `atomicity`, `support`; empty when the vocabulary does
    /// not say.
    pub family: String,
    /// Drawn from the target to the declaring threat, under `inverse`.
    pub reversed: bool,
    /// The family's `from` relation, the label of a reversed link.
    pub inverse: String,
    /// Drawn both ways.
    pub bidirectional: bool,
}

impl ChainingRelation {
    /// The label of the link as drawn.
    pub fn drawn_label(&self) -> &str {
        if self.reversed && !self.inverse.is_empty() {
            &self.inverse
        } else {
            &self.label
        }
    }
}

/// The vocabularies pages read.
pub struct Vocab<'v> {
    vocabularies: &'v Vocabularies,
}

impl<'v> Vocab<'v> {
    /// Over `vocabularies`.
    pub fn new(vocabularies: &'v Vocabularies) -> Self {
        Self { vocabularies }
    }

    /// The entry `key` names in `field`: by key once the stage prefix is
    /// resolved, else the entry whose `legacy` is the key.
    fn entry(&self, field: &str, key: &str) -> Option<Entry> {
        let vocabulary = self.vocabularies.get(field)?;
        let resolved = self.vocabularies.identifier(field, key);
        if let Some(entry) = vocabulary.entries.get(resolved) {
            return Some(entry.clone());
        }
        vocabulary
            .entries
            .values()
            .find(|entry| {
                entry
                    .extra
                    .get("legacy")
                    .and_then(|value| value.as_str())
                    .is_some_and(|legacy| legacy == resolved)
            })
            .cloned()
    }

    /// `enrich(field, key)`.
    pub fn enrich(&self, field: &str, key: &str) -> Enriched {
        let Some(entry) = self.entry(field, key) else {
            return Enriched {
                key: key.to_owned(),
                label: key.to_owned(),
                ..Enriched::default()
            };
        };
        let label = if entry.name.is_empty() {
            entry
                .extra
                .get("label")
                .and_then(|value| value.as_str())
                .filter(|label| !label.is_empty())
                .unwrap_or(key)
                .to_owned()
        } else {
            entry.name.clone()
        };
        Enriched {
            key: key.to_owned(),
            label,
            description: entry.description.clone(),
            link: entry.link.clone(),
            id: entry
                .extra
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_owned(),
            stages: entry.stages.clone(),
            found: true,
        }
    }

    /// One field of an entry as `get_vocab_entry(…, field=…)` gives it:
    /// newlines dropped, empty when unset.
    pub fn description(&self, field: &str, key: &str) -> String {
        self.entry(field, key)
            .map(|entry| entry.description.replace('\n', ""))
            .unwrap_or_default()
    }

    /// The extra key `name` of an entry, as text (`tide.vocab.relation.type`).
    pub fn extra(&self, field: &str, key: &str, name: &str) -> String {
        self.entry(field, key)
            .and_then(|entry| {
                entry
                    .extra
                    .get(name)
                    .and_then(|value| value.as_str().map(str::to_owned))
            })
            .unwrap_or_default()
    }

    /// The name and description of the stage `id` of `field`
    /// (`get_vocab_stage_details`).
    pub fn stage(&self, field: &str, id: &str) -> Option<(String, String)> {
        let vocabulary = self.vocabularies.get(field)?;
        vocabulary
            .metadata
            .stages
            .iter()
            .find(|stage| stage.id.as_deref() == Some(id))
            .map(|stage| {
                (
                    stage.name.clone().unwrap_or_default(),
                    stage.description.clone().unwrap_or_default(),
                )
            })
    }

    /// The entry keys of `field`, in the vocabulary's order
    /// (`vocabulary_order`).
    pub fn order(&self, field: &str) -> Vec<String> {
        self.vocabularies
            .get(field)
            .map(|vocabulary| vocabulary.entries.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// ATT&CK's tactics in matrix order, as the vocabulary's release names
    /// them (`attack_tactics`).
    pub fn attack_tactics(&self) -> Vec<String> {
        self.vocabularies
            .get("att&ck")
            .map(|vocabulary| {
                vocabulary
                    .metadata
                    .stages
                    .iter()
                    .filter_map(|stage| stage.name.clone().filter(|name| !name.is_empty()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The tactics a technique serves, each once, in matrix order
    /// (`technique_tactics`).
    pub fn technique_tactics(&self, technique: &str, order: &[String]) -> Vec<String> {
        let mut tactics: Vec<String> = Vec::new();
        for tactic in self.enrich("att&ck", technique).stages {
            if !tactic.is_empty() && !tactics.contains(&tactic) {
                tactics.push(tactic);
            }
        }
        let position = |tactic: &String| {
            order
                .iter()
                .position(|known| known == tactic)
                .unwrap_or(order.len())
        };
        tactics.sort_by_key(position);
        tactics
    }

    /// The kill-chain stage `phase` belongs to (its entry's first stage, else
    /// the phase itself), or empty when the vocabulary has no such phase
    /// (`killchain_stage`).
    pub fn killchain_stage(&self, phase: &str) -> String {
        let Some(vocabulary) = self.vocabularies.get("killchain") else {
            return String::new();
        };
        let Some(entry) = vocabulary.entries.get(phase) else {
            return String::new();
        };
        entry
            .stages
            .first()
            .filter(|stage| !stage.is_empty())
            .cloned()
            .unwrap_or_else(|| phase.to_owned())
    }

    /// Other names of an ATT&CK group (`att&ck::G0016` is also Cozy Bear),
    /// without the group's own name (`actor_aliases`).
    pub fn actor_aliases(&self, actor: &str) -> Vec<String> {
        let id = actor.rsplit("::").next().unwrap_or(actor);
        let Some(vocabulary) = self.vocabularies.get("att&ck.groups") else {
            return Vec::new();
        };
        let Some(entry) = vocabulary.entries.get(id) else {
            return Vec::new();
        };
        let Some(aliases) = entry.extra.get("alias").and_then(|value| value.as_array()) else {
            return Vec::new();
        };
        aliases
            .iter()
            .filter_map(|alias| alias.as_str())
            .filter(|alias| !alias.is_empty() && *alias != entry.name)
            .map(str::to_owned)
            .collect()
    }

    /// The kill chain's stages in order, each with its phases in order
    /// (`killchain_stages`): the stages the vocabulary declares, then any
    /// other; a phase without a stage is a group of its own name. Empty
    /// stages are left out.
    pub fn killchain_stages(&self) -> Vec<(String, Vec<String>)> {
        let Some(vocabulary) = self.vocabularies.get("killchain") else {
            return Vec::new();
        };
        let mut groups: Vec<(String, Vec<String>)> = vocabulary
            .metadata
            .stages
            .iter()
            .filter_map(|stage| stage.name.clone().filter(|name| !name.is_empty()))
            .map(|name| (name, Vec::new()))
            .collect();
        for (key, entry) in &vocabulary.entries {
            let stage = entry
                .stages
                .first()
                .filter(|stage| !stage.is_empty())
                .cloned()
                .unwrap_or_else(|| key.clone());
            match groups.iter_mut().find(|(name, _)| *name == stage) {
                Some((_, phases)) => phases.push(key.clone()),
                None => groups.push((stage, vec![key.clone()])),
            }
        }
        groups.retain(|(_, phases)| !phases.is_empty());
        groups
    }

    /// How a chaining relation is drawn (`chaining_relation`): its label,
    /// its family (the entry's first stage), and whether the vocabulary
    /// draws it from the target (`to`, under the family's `from` relation)
    /// or both ways. A key the vocabulary does not have is a plain forward
    /// link labelled with the key.
    pub fn chaining_relation(&self, key: &str) -> ChainingRelation {
        let plain = ChainingRelation {
            label: key.to_owned(),
            ..ChainingRelation::default()
        };
        let Some(vocabulary) = self.vocabularies.get("chaining_relations") else {
            return plain;
        };
        let Some(entry) = vocabulary.entries.get(key) else {
            return plain;
        };
        let kind = |entry: &opentide_schema::vocab::Entry| {
            entry
                .extra
                .get("tide.vocab.relation.type")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_owned()
        };
        let family = entry.stages.first().cloned().unwrap_or_default();
        let relation_type = kind(entry);
        let inverse = if relation_type == "to" {
            vocabulary
                .entries
                .iter()
                .find(|(_, other)| {
                    kind(other) == "from"
                        && other.stages.first().cloned().unwrap_or_default() == family
                })
                .map(|(other_key, other)| {
                    if other.name.is_empty() {
                        other_key.clone()
                    } else {
                        other.name.clone()
                    }
                })
                .unwrap_or_default()
        } else {
            String::new()
        };
        ChainingRelation {
            label: if entry.name.is_empty() {
                key.to_owned()
            } else {
                entry.name.clone()
            },
            family,
            reversed: relation_type == "to",
            inverse,
            bidirectional: relation_type == "bidirectional",
        }
    }
}
