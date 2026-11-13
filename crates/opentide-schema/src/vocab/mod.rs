//! Vocabularies (RFC 0003): loading, pinned resolution, scoped values,
//! stages, suggestions, the ATT&CK matrix and Sentinel's ATT&CK v18 list.
//!
//! - [`Vocabulary`]: one `{field}.vocab.toml` document.
//! - [`Vocabularies`]: the set a workspace resolves against: the bundled
//!   documents ([`bundled`], parsed on first use), or the documents of a data
//!   root that replaces them (`OPENTIDE_DATA_ROOT`), plus the vocabularies a
//!   workspace's own objects make (`threat`, `objective`, `rule`, inserted by
//!   whoever indexes the objects).
//! - [`Selector`]: what a schema field asks for (`tide.vocab`,
//!   `tide.vocab.scoped`, `tide.vocab.stages`); [`Vocabularies::allowed`],
//!   [`Vocabularies::is_valid`] and [`Vocabularies::check`] resolve a value
//!   against it, and [`Vocabularies::suggest`] says what an unknown value most
//!   likely means ([`opentide_core::suggest`]).
//! - [`attack`]: the ATT&CK Enterprise matrix `info catalog` shows.
//! - [`sentinel`]: the ATT&CK v18 ids Microsoft Sentinel accepts.
//!
//! The crate stays I/O-free: documents come in as text, from the bundle
//! (`include_str!`) or from the caller.

pub mod attack;
pub mod bundled;
mod document;
pub mod sentinel;
mod version;

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use opentide_core::suggest::Candidates;

use indexmap::{IndexMap, IndexSet};

pub use document::{Entry, KeyKind, Metadata, SUFFIX, Stage, Vocabulary};
pub use version::{Contract, Version, VocabRef};

/// The object families whose workspace objects form vocabularies of their
/// own, keyed by UUID (`CORE_OBJECT_TYPES`).
pub const OBJECT_TYPES: [&str; 3] = ["threat", "objective", "rule"];

/// A vocabulary that cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VocabError {
    /// A file name without the `.vocab.toml` suffix.
    #[error("not a vocabulary file: {0}")]
    NotAVocabularyFile(String),
    /// The document is not TOML.
    #[error("could not read vocabulary TOML {file}: {message}")]
    Toml {
        /// The file.
        file: String,
        /// The parser's message.
        message: String,
    },
    /// A required top-level key is missing.
    #[error("missing required key {key:?} in vocabulary document: {file}")]
    MissingKey {
        /// The file.
        file: String,
        /// The key.
        key: String,
    },
    /// A top-level key has the wrong type or value.
    #[error("invalid {key:?} in vocabulary document {file}: {why}")]
    InvalidKey {
        /// The file.
        file: String,
        /// The key.
        key: String,
        /// What is wrong with it.
        why: String,
    },
    /// The document's `field` is not its file name's stem.
    #[error("vocabulary field {field:?} does not match filename {expected:?} in {file}")]
    FieldMismatch {
        /// The file.
        file: String,
        /// The `field` the document declares.
        field: String,
        /// The file name's stem.
        expected: String,
    },
    /// Two entries share a key.
    #[error("duplicate entry key {key:?} in vocabulary {file} at index {index}")]
    DuplicateKey {
        /// The file.
        file: String,
        /// The key.
        key: String,
        /// The second entry's index.
        index: usize,
    },
    /// A version that is not `M.m`.
    #[error("invalid vocabulary version: {0:?}")]
    InvalidVersion(String),
    /// A contract that is not `field::M.m`.
    #[error("invalid vocabulary contract: {0:?}")]
    InvalidContract(String),
}

/// The vocabularies a workspace resolves values against.
#[derive(Debug, Clone)]
pub struct Vocabularies {
    own: IndexMap<String, Arc<Vocabulary>>,
    bundled: bool,
}

impl Default for Vocabularies {
    /// The bundled vocabularies.
    fn default() -> Self {
        Self::bundled()
    }
}

impl Vocabularies {
    /// The vocabularies opentide ships.
    pub fn bundled() -> Self {
        Self {
            own: IndexMap::new(),
            bundled: true,
        }
    }

    /// The vocabularies of a data root that replaces the bundled ones
    /// (`OPENTIDE_DATA_ROOT`): each `(file name, text)` of its `vocabulary/`
    /// directory. A document that cannot be read is left out and returned
    /// with its error, so one bad file does not hide the others.
    pub fn from_files<'a>(
        files: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> (Self, Vec<VocabError>) {
        let mut set = Self {
            own: IndexMap::new(),
            bundled: false,
        };
        let mut errors = Vec::new();
        for (name, text) in files {
            if !name.ends_with(SUFFIX) {
                continue;
            }
            match Vocabulary::from_file(name, text) {
                Ok(vocabulary) => {
                    set.insert(vocabulary);
                }
                Err(error) => errors.push(error),
            }
        }
        (set, errors)
    }

    /// Adds `vocabulary`, replacing one of the same field (a workspace's
    /// object vocabularies, or a document that overrides a bundled one).
    pub fn insert(&mut self, vocabulary: Vocabulary) -> &mut Self {
        self.own
            .insert(vocabulary.field().to_owned(), Arc::new(vocabulary));
        self
    }

    /// The vocabulary `field`.
    pub fn get(&self, field: &str) -> Option<Arc<Vocabulary>> {
        self.own.get(field).cloned().or_else(|| {
            if self.bundled {
                bundled::get(field)
            } else {
                None
            }
        })
    }

    /// The fields of every vocabulary, sorted.
    pub fn fields(&self) -> BTreeSet<&str> {
        let mut fields: BTreeSet<&str> = self.own.keys().map(String::as_str).collect();
        if self.bundled {
            fields.extend(bundled::fields().map(|field| -> &str { field }));
        }
        fields
    }

    /// What a field that asks for `selector` accepts: resolve once, then
    /// check every value of the field against the [`Resolved`] set.
    ///
    /// - A pin keeps the entries active at it ([`Entry::active_at`]).
    /// - An id-keyed vocabulary, or one of the [`OBJECT_TYPES`], gives its
    ///   keys; scoped, each prefixed with its first stage
    ///   (`att&ck::G0006`, `misp::<uuid>`). A stage filter does not apply.
    /// - A name-keyed vocabulary gives the keys in one of the stages the
    ///   field asks for (every key, without a filter); scoped, one value per
    ///   such stage (`OS::Windows::Desktop`), so a key without stages gives
    ///   none.
    ///
    /// A vocabulary that does not exist accepts nothing. Editor search hints
    /// (`T1059 #Command and Scripting Interpreter`) are not values: they
    /// belong to the generated schemas (UC-1.8), where an editor inserts them
    /// and YAML reads the `#` as a comment.
    pub fn resolve(&self, selector: &Selector) -> Resolved {
        let vocabulary = self.get(&selector.vocab.field);
        let mut values: IndexSet<String> = IndexSet::new();
        if let Some(vocabulary) = &vocabulary {
            let model = vocabulary.metadata.key == KeyKind::Id
                || OBJECT_TYPES.contains(&selector.vocab.field.as_str());
            let filter: &[String] = &selector.stages;
            for entry in vocabulary
                .entries
                .values()
                .filter(|entry| selector.vocab.pin.is_none_or(|pin| entry.active_at(pin)))
            {
                if model {
                    match entry.stages.first() {
                        Some(stage) if selector.scoped => {
                            values.insert(format!("{stage}::{}", entry.key));
                        }
                        _ => {
                            values.insert(entry.key.clone());
                        }
                    }
                    continue;
                }
                let mut matching = entry
                    .stages
                    .iter()
                    .filter(|stage| filter.is_empty() || filter.contains(stage))
                    .peekable();
                if selector.scoped {
                    for stage in matching {
                        values.insert(format!("{stage}::{}", entry.key));
                    }
                } else if filter.is_empty() || matching.peek().is_some() {
                    values.insert(entry.key.clone());
                }
            }
        }
        Resolved {
            vocab: selector.vocab.to_string(),
            vocabulary,
            values,
            candidates: OnceLock::new(),
        }
    }

    /// The values a field that asks for `selector` accepts, in the
    /// vocabulary's order, without duplicates ([`Self::resolve`]).
    pub fn allowed(&self, selector: &Selector) -> Vec<String> {
        self.resolve(selector).values.into_iter().collect()
    }

    /// The key `value` names in the vocabulary of `field`: `value` itself
    /// when it is a key, else `value` without a leading stage id
    /// (`OS::Windows::Desktop` → `Windows::Desktop`). Raw first, so a key that
    /// begins with a stage id (`Security::Kerberos`) is never stripped into
    /// another key.
    pub fn identifier<'v>(&self, field: &str, value: &'v str) -> &'v str {
        identifier(self.get(field).as_deref(), value)
    }

    /// [`Resolved::is_valid`], resolving `selector` for one value.
    pub fn is_valid(&self, value: &str, selector: &Selector) -> bool {
        self.resolve(selector).is_valid(value)
    }

    /// [`Resolved::suggest`], resolving `selector` for one value.
    pub fn suggest(&self, value: &str, selector: &Selector) -> Option<String> {
        self.resolve(selector).suggest(value)
    }

    /// [`Resolved::check`], resolving `selector` for one value.
    pub fn check(&self, value: &str, selector: &Selector) -> Option<Unknown> {
        self.resolve(selector).check(value)
    }
}

/// The values one field accepts ([`Vocabularies::resolve`]).
#[derive(Debug, Clone)]
pub struct Resolved {
    vocab: String,
    vocabulary: Option<Arc<Vocabulary>>,
    values: IndexSet<String>,
    /// The values prepared for suggestions, on the first unknown value.
    candidates: OnceLock<Candidates>,
}

impl Resolved {
    /// The accepted values, in the vocabulary's order.
    pub fn values(&self) -> impl Iterator<Item = &str> {
        self.values.iter().map(String::as_str)
    }

    /// Whether the field accepts `value`, written with or without its stage
    /// prefix ([`Vocabularies::identifier`]).
    pub fn is_valid(&self, value: &str) -> bool {
        self.values.contains(value)
            || self
                .values
                .contains(identifier(self.vocabulary.as_deref(), value))
    }

    /// What `value`, which the field does not accept, most likely means: the
    /// value without its stage prefix when that is accepted, else the
    /// closest accepted value ([`opentide_core::suggest`]) to the value as
    /// written or, failing that, to its key (`Host::Proces` → `Process` on a
    /// field whose values carry no stage). Nothing for a UUID or
    /// `misp::<uuid>` (an identifier is not a typo) or a vocabulary that does
    /// not exist.
    pub fn suggest(&self, value: &str) -> Option<String> {
        if is_opaque_identifier(value) || self.values.is_empty() {
            return None;
        }
        let stripped = self
            .vocabulary
            .as_deref()
            .map_or(value, |vocabulary| strip_stage(vocabulary, value));
        if self.values.contains(stripped) {
            return Some(stripped.to_owned());
        }
        let candidates = self
            .candidates
            .get_or_init(|| Candidates::new(self.values.iter().map(String::as_str)));
        candidates
            .closest(value)
            .or_else(|| {
                (stripped != value)
                    .then(|| candidates.closest(stripped))
                    .flatten()
            })
            .and_then(|index| self.values.get_index(index))
            .cloned()
    }

    /// `None` when the field accepts `value`, else the `vocab_unknown`
    /// finding, with its suggestion.
    pub fn check(&self, value: &str) -> Option<Unknown> {
        if self.is_valid(value) {
            return None;
        }
        Some(Unknown {
            vocab: self.vocab.clone(),
            value: value.to_owned(),
            suggestion: self.suggest(value),
        })
    }
}

fn identifier<'v>(vocabulary: Option<&Vocabulary>, value: &'v str) -> &'v str {
    match vocabulary {
        Some(vocabulary) if vocabulary.entries.contains_key(value) => value,
        Some(vocabulary) => strip_stage(vocabulary, value),
        None => value,
    }
}

fn strip_stage<'v>(vocabulary: &Vocabulary, value: &'v str) -> &'v str {
    match value.split_once("::") {
        Some((stage, rest)) if vocabulary.stage_ids().any(|id| id == stage) => rest,
        _ => value,
    }
}

/// A UUID, or a MISP actor id (`misp::<uuid>`): identifiers, not typos.
fn is_opaque_identifier(value: &str) -> bool {
    let value = value.trim();
    let uuid = value.strip_prefix("misp::").unwrap_or(value);
    let bytes = uuid.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// What a schema field asks of a vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Selector {
    /// `tide.vocab`: the vocabulary, pinned or not.
    pub vocab: VocabRef,
    /// `tide.vocab.scoped`: values carry their stage (`OS::Windows`).
    pub scoped: bool,
    /// `tide.vocab.stages`: only these stages; empty for all.
    pub stages: Vec<String>,
}

impl Selector {
    /// Every entry of `vocab`, unscoped.
    pub fn new(vocab: VocabRef) -> Self {
        Self {
            vocab,
            scoped: false,
            stages: Vec::new(),
        }
    }

    /// Values carry their stage.
    pub fn scoped(mut self, scoped: bool) -> Self {
        self.scoped = scoped;
        self
    }

    /// Only these stages.
    pub fn stages<S: Into<String>>(mut self, stages: impl IntoIterator<Item = S>) -> Self {
        self.stages = stages.into_iter().map(Into::into).collect();
        self
    }
}

/// A value its field's vocabulary does not hold: the `vocab_unknown` finding
/// ([`opentide_core::codes::VOCAB_UNKNOWN`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unknown {
    /// The vocabulary reference as the schema writes it (`tlp::1.0`).
    pub vocab: String,
    /// The value.
    pub value: String,
    /// The value it most likely means.
    pub suggestion: Option<String>,
}

impl Unknown {
    /// The code.
    pub const CODE: &'static str = opentide_core::codes::VOCAB_UNKNOWN;

    /// The finding's message: `Value "clearr" is not a valid "tlp::1.0"
    /// vocabulary entry`.
    pub fn message(&self) -> String {
        format!(
            "Value {} is not a valid {} vocabulary entry",
            quote(&self.value),
            quote(&self.vocab)
        )
    }

    /// The help line: `did you mean "clear"?`.
    pub fn help(&self) -> Option<String> {
        self.suggestion
            .as_deref()
            .map(|suggestion| format!("did you mean {}?", quote(suggestion)))
    }
}

/// `text` quoted as every message quotes a value: in double quotes, with
/// Rust's escapes for a backslash, a quote and every character that does
/// not show (`\n`, `\u{7}`, `\u{a0}`, `\u{200b}`), so a value that only
/// looks valid (`High` and a no-break space) shows what it holds.
pub fn quote(text: &str) -> String {
    format!("{text:?}")
}

#[cfg(test)]
mod tests;
