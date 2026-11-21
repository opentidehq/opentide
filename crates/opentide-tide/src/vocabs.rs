//! The Tide vocabularies the editor reads, pre-parsed at build time.
//!
//! They are the one bundled set, `src/opentide/data/vocabulary`, which
//! opentide-schema compiles in for `validate` and the upstream sync
//! (`.github/workflows/vocab-upstream.yml`) writes: a second copy under
//! `data/catalogs/tide/vocabs` had drifted by 538 lines of `actors` alone
//! before UC-1.6 ([#812](https://github.com/opentidehq/opentide/issues/812)).
//!
//! `build.rs` parses every vocabulary file once ([`crate::vocab_model`]) and
//! stores the result as one compressed postcard blob (#1743); the first reader
//! decodes it, with no TOML parse at run time.

use std::collections::BTreeMap;
use std::sync::OnceLock;

pub use crate::vocab_model::{Vocab, VocabKey};

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

pub fn bundled_vocabs() -> &'static BTreeMap<String, Vocab> {
    static INDEX: OnceLock<BTreeMap<String, Vocab>> = OnceLock::new();
    INDEX.get_or_init(|| {
        opentide_dataset::compiled_value::<Vec<Vocab>>(
            "vocabularies",
            opentide_dataset::blob!("vocabularies"),
        )
        .into_iter()
        .map(|vocab| (vocab.field.clone(), vocab))
        .collect()
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
        assert_eq!(v.len(), 34, "expected 34 vocabs, got {}", v.len());
        assert!(!v.contains_key("stakeholders"));
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
