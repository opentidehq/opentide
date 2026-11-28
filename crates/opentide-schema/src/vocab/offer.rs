//! What a field that names a vocabulary offers: the values, a Markdown
//! dropdown and a plain description for each ([`Offer`]), worked out from one
//! vocabulary document.
//!
//! The offer of a bundled vocabulary is a function of the bundled document
//! alone, so `build.rs` makes it once for each field (this file is compiled
//! into the build script as well) and the crate reads it from the compiled-in
//! data ([`bundled_offer`](super::bundled_offer)); a workspace's own vocabularies, a data root's, a
//! pin, and a field that asks for unwrapped hints are worked out at run time
//! by [`offer_of`] and kept by `Vocabularies::memoized`.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use super::{Entry, KeyKind, OBJECT_TYPES, VocabRef, Vocabulary, first_sentence, plain_text};

/// The values, Markdown dropdowns and plain descriptions a field offers.
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Offer {
    /// The values offered (the `enum`).
    pub values: Vec<String>,
    /// A Markdown dropdown for each.
    pub markdown: Vec<String>,
    /// A plain description for each.
    pub plain: Vec<String>,
    /// The display name of each value's entry, empty where the offer has
    /// none (a configured status, a tenant). An editor shows it beside the
    /// value.
    pub names: Vec<String>,
    /// What an editor matches each value by besides the value itself: the
    /// entry's name and aliases (`Abuse Elevation Control Mechanism`), empty
    /// where the offer has none. A search hint is the value, `#` and this.
    pub search: Vec<String>,
}

/// The values of an [`Offer`] with their names and search text alone: what an
/// editor's list of values reads, without the Markdown of each (a bundled
/// vocabulary's descriptions are most of its offer, and a list shows none).
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OfferNames {
    /// The values offered.
    pub values: Vec<String>,
    /// [`Offer::names`].
    pub names: Vec<String>,
    /// [`Offer::search`].
    pub search: Vec<String>,
}

impl Offer {
    /// Its values with their names and search text.
    pub fn offer_names(&self) -> OfferNames {
        OfferNames {
            values: self.values.clone(),
            names: self.names.clone(),
            search: self.search.clone(),
        }
    }
}

/// How a field asks for a vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VocabOptions {
    /// Values carry their first stage (`OS::Windows::Desktop`).
    pub scoped: bool,
    /// Search hints are not abbreviated.
    pub no_wrap: bool,
}

/// The longest stage description a dropdown quotes, in characters.
const STAGE_DESCRIPTION_LIMIT: usize = 300;

/// The abbreviations that shorten a search hint longer than [`HINT_WRAP`]
/// characters: each replaces a whole word, never part of one, and none
/// drops a word (`Use` once took the first letters of `User`, so a hint read
/// `Bypass  r Account Control`).
pub(crate) const HINT_ABBREVIATIONS: [(&str, &str); 3] =
    [("and", "&"), ("without", "w/o"), ("with", "w/")];

/// The length past which a search hint is abbreviated.
const HINT_WRAP: usize = 60;

/// The values, dropdowns and plain descriptions of one vocabulary reference
/// (`field` or `field::M.m`). The values are [`Vocabularies::allowed`](super::Vocabularies::allowed)'s;
/// a model vocabulary (keyed by id, or a workspace's objects) also offers a
/// search hint per value (`T1059 #Command and Scripting Interpreter`),
/// unless its document turns them off. A vocabulary that gives no value
/// offers the empty string, so the field is never left without an `enum`.
pub fn offer_of(vocabulary: &Vocabulary, vocab: &VocabRef, options: VocabOptions) -> Offer {
    let mut offer = Offer::default();
    let model =
        vocabulary.metadata.key == KeyKind::Id || OBJECT_TYPES.contains(&vocab.field.as_str());
    let hints = model && vocabulary.search_hints();
    let mut hint_offer = Offer::default();
    // The values offered so far: a lookup, not a scan of `offer.values` that
    // builds a JSON string per comparison (quadratic in a vocabulary's size).
    let mut offered: HashSet<String> = HashSet::new();
    let active = vocabulary
        .entries
        .values()
        .filter(|entry| vocab.pin.is_none_or(|pin| entry.active_at(pin)));
    for entry in active {
        let mut emit = |offer: &mut Offer, value: String, stages: &[String]| -> bool {
            if !offered.insert(value.clone()) {
                return false;
            }
            offer.markdown.push(dropdown(vocabulary, entry, stages));
            offer.plain.push(plain(&value, entry));
            offer.names.push(entry.name.trim().to_owned());
            offer.search.push(search_text(entry));
            offer.values.push(value);
            true
        };
        if model {
            let value = match entry.stages.first() {
                Some(stage) if options.scoped => format!("{stage}::{}", entry.key),
                _ => entry.key.clone(),
            };
            if emit(&mut offer, value.clone(), &entry.stages) && hints {
                hint_offer
                    .values
                    .push(search_hint(&value, entry, options.no_wrap));
                hint_offer.markdown.extend(offer.markdown.last().cloned());
                hint_offer.plain.extend(offer.plain.last().cloned());
                hint_offer.names.extend(offer.names.last().cloned());
                hint_offer.search.extend(offer.search.last().cloned());
            }
            continue;
        }
        if options.scoped {
            for stage in &entry.stages {
                emit(
                    &mut offer,
                    format!("{stage}::{}", entry.key),
                    std::slice::from_ref(stage),
                );
            }
        } else {
            emit(&mut offer, entry.key.clone(), &entry.stages);
        }
    }
    if offer.values.is_empty() {
        offer.values.push(String::new());
    }
    offer.values.extend(hint_offer.values);
    offer.markdown.extend(hint_offer.markdown);
    offer.plain.extend(hint_offer.plain);
    offer.names.extend(hint_offer.names);
    offer.search.extend(hint_offer.search);
    offer
}

/// A string from an entry's other keys.
fn extra<'e>(entry: &'e Entry, key: &str) -> Option<&'e str> {
    entry
        .extra
        .get(key)
        .and_then(toml::Value::as_str)
        .filter(|text| !text.is_empty())
}

/// An entry's name, then its aliases, separated by `, `: what an editor
/// matches its value by besides the value.
pub(crate) fn search_text(entry: &Entry) -> String {
    let mut tips = entry.name.clone();
    if let Some(toml::Value::Array(aliases)) = entry.extra.get("alias")
        && !aliases.is_empty()
    {
        let aliases: Vec<String> = aliases
            .iter()
            .map(|alias| {
                alias
                    .as_str()
                    .map_or_else(|| alias.to_string(), str::to_owned)
            })
            .collect();
        tips.push_str(", ");
        tips.push_str(&aliases.join(", "));
    }
    tips.trim().to_owned()
}

/// The text an editor searches: the value, then `#` and the entry's name
/// and aliases ([`search_text`]), abbreviated past [`HINT_WRAP`] characters
/// unless the field says not to wrap. YAML reads what follows ` #` as a
/// comment, so a hint a third-party editor inserts is still the value.
pub(crate) fn search_hint(value: &str, entry: &Entry, no_wrap: bool) -> String {
    let tips = search_text(entry);
    let hint = format!("{value} #{tips}");
    if no_wrap || hint.chars().count() <= HINT_WRAP {
        return hint;
    }
    format!("{value} #{}", abbreviate(&tips))
}

/// `text` with each whole word of [`HINT_ABBREVIATIONS`] abbreviated: a
/// word is what lies between two spaces, so `Used`, `User` and `and,` are
/// left as they are.
fn abbreviate(text: &str) -> String {
    text.split(' ')
        .map(|word| {
            HINT_ABBREVIATIONS
                .iter()
                .find(|(long, _)| *long == word)
                .map_or(word, |(_, short)| *short)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Plain hover text: the entry's name (unless the value ends with it), then
/// the first sentence of its description.
fn plain(value: &str, entry: &Entry) -> String {
    let display = if entry.name.is_empty() {
        entry.key.trim()
    } else {
        entry.name.trim()
    };
    let description = summary(&entry.description);
    if !display.is_empty() && !value.ends_with(display) {
        if description.is_empty() {
            display.to_owned()
        } else {
            format!("{display}: {description}")
        }
    } else {
        description
    }
}

/// The first sentence of `description` as plain text, worked out once per
/// distinct description. One `generate schemas` offers a vocabulary in many
/// fields of every schema and in the field catalog, and the Markdown
/// clean-up of its descriptions was most of the phase's time (each
/// `opentide new` that generates the schemas first paid it again per
/// field). Keyed by the text itself, so an edited description is a miss,
/// never a stale answer.
fn summary(description: &str) -> String {
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    summary_in(
        CACHE.get_or_init(Mutex::default),
        SUMMARY_LIMIT,
        description,
    )
}

/// How many descriptions [`summary`] keeps before it starts over: more
/// than every bundled vocabulary holds, so a long-running process (the
/// language server) that sees many workspaces stays bounded.
const SUMMARY_LIMIT: usize = 1 << 16;

/// [`summary`] with its cache and bound given.
pub(crate) fn summary_in(
    cache: &Mutex<HashMap<String, String>>,
    limit: usize,
    description: &str,
) -> String {
    if let Some(found) = cache
        .lock()
        .ok()
        .and_then(|cache| cache.get(description).cloned())
    {
        return found;
    }
    let computed = first_sentence(&plain_text(description, true));
    if let Ok(mut cache) = cache.lock() {
        if cache.len() >= limit {
            cache.clear();
        }
        cache.insert(description.to_owned(), computed.clone());
    }
    computed
}

/// The Markdown an editor shows for an entry in a dropdown: its name, its
/// identifier and vocabulary, its level and TLP (an object), its stages, its
/// link and its description; empty parts are left out.
pub(crate) fn dropdown(vocabulary: &Vocabulary, entry: &Entry, stages: &[String]) -> String {
    let identifier = extra(entry, "id").unwrap_or(&entry.key);
    let mut display = if entry.name.is_empty() {
        entry.key.clone()
    } else {
        entry.name.clone()
    };
    // An all-lower-case name is title-cased by English rules (the
    // `titlecase` crate: `command and control` is `Command and Control`).
    if display.chars().any(char::is_alphabetic) && !display.chars().any(char::is_uppercase) {
        display = titlecase::titlecase(&display);
    }
    let mut parts = vec![
        format!("### {display}"),
        format!("**Identifier**: `{identifier}`"),
        format!("_Vocabulary_ : `{}`", vocabulary.metadata.name),
    ];
    let mut level = String::new();
    if OBJECT_TYPES.contains(&vocabulary.field()) {
        level = ["criticality", "priority", "severity"]
            .iter()
            .zip(["Criticality", "Priority", "Severity"])
            .find_map(|(key, label)| {
                entry
                    .extra
                    .get(*key)
                    .map(|value| {
                        value
                            .as_str()
                            .map_or_else(|| value.to_string(), str::to_owned)
                    })
                    .filter(|value| !value.is_empty())
                    .map(|value| format!("**{label}**: {value}"))
            })
            .unwrap_or_else(|| "**Criticality**: No Criticality Assigned".to_owned());
    }
    if let Some(tlp) = extra(entry, "tlp") {
        let tlp = format!("**TLP:{}**", tlp.to_uppercase());
        level = if level.is_empty() {
            tlp
        } else {
            format!("{level} | {tlp}")
        };
    }
    if !level.is_empty() {
        parts.push(level);
    }
    if !stages.is_empty() {
        let documented = stage_doc(vocabulary, stages);
        parts.push(if documented.is_empty() {
            format!("`{}`", stages.join(", "))
        } else {
            documented
        });
    }
    if !entry.link.is_empty() {
        parts.push(entry.link.clone());
    }
    parts.push("---".to_owned());
    if !entry.description.is_empty() {
        parts.push(entry.description.to_string());
    }
    let mut text = parts.join("\n\n");
    text.push('\n');
    text
}

/// Each stage's name and description, from the vocabulary's stages.
fn stage_doc(vocabulary: &Vocabulary, stages: &[String]) -> String {
    let mut parts = Vec::new();
    for stage in stages {
        let Some(found) = vocabulary.metadata.stages.iter().find(|candidate| {
            candidate.id.as_deref().or(candidate.name.as_deref()) == Some(stage.as_str())
        }) else {
            continue;
        };
        let name = found.name.as_deref().unwrap_or(stage);
        let mut description = found
            .description
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_owned();
        if description.chars().count() > STAGE_DESCRIPTION_LIMIT {
            description = description.chars().take(STAGE_DESCRIPTION_LIMIT).collect();
            description.push_str("...");
        }
        parts.push(format!("**{name}**: _{description}_"));
    }
    parts.join("\n\n")
}
