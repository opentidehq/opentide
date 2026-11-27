//! The per-language `KEYWORDS` input of the TextMate generator (epic #1219).
//!
//! A language's TextMate grammar lists its keywords and punctuation, each
//! with the `HighlightSpec` capture that colours it: the pairs of its table
//! (its file under `keywords/`). The tables were first written out of the
//! tree-sitter `highlights.scm` queries (#1219), and generate the same bytes
//! those did; [`generate_tm_language`](crate::generate_tm_language) groups
//! the pairs by capture, so their order does not matter.
//!
//! The tables live in this crate, not in the language crates, because the
//! language crates depend on it (`xtask/layers.toml`). A language's lexer is
//! checked against its table from the language crate's own tests.

use opentide_core::LanguageId;
use std::collections::{BTreeMap, BTreeSet};

/// The name of a `HighlightSpec` capture, as `highlights/spec.toml` spells
/// it. The names are a frozen contract: renaming one is a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capture(&'static str);

impl Capture {
    /// The capture called `name`. A table is checked against the spec by
    /// the `keyword_tables_name_spec_captures` test.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    /// The capture's name in `highlights/spec.toml`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.0
    }
}

/// The captures a query language's table uses, as `highlights/spec.toml`
/// names them (checked by the `capture_constants_name_spec_captures` test).
impl Capture {
    pub const COMMENT: Self = Self::new("comment");
    pub const KEYWORD: Self = Self::new("keyword");
    pub const OPERATOR: Self = Self::new("operator");
    pub const PIPE: Self = Self::new("operator.pipe");
    pub const FUNCTION: Self = Self::new("function");
    pub const FUNCTION_BUILTIN: Self = Self::new("function.builtin");
    pub const TYPE: Self = Self::new("type");
    pub const VARIABLE: Self = Self::new("variable");
    pub const PROPERTY: Self = Self::new("property");
    pub const STRING: Self = Self::new("string");
    pub const NUMBER: Self = Self::new("number");
    pub const BOOLEAN: Self = Self::new("boolean");
    pub const CONSTANT: Self = Self::new("constant");
    pub const PUNCTUATION: Self = Self::new("punctuation");
    pub const BRACKET: Self = Self::new("punctuation.bracket");
    pub const DELIMITER: Self = Self::new("punctuation.delimiter");
    pub const ERROR: Self = Self::new("error");
    pub const MACRO: Self = Self::new("macro");
}

/// A language's keywords and punctuation, each with its capture.
pub type Keywords = &'static [(&'static str, Capture)];

/// The table of each language, one file each.
mod cql;
mod datadog;
mod eql;
mod esql;
mod exabeam;
mod falco;
mod kql;
mod kuery;
mod lucene;
mod spl;
mod yara;
mod yaral;

/// The `KEYWORDS` table of `language`; `None` for Tide YAML and the
/// configuration, which are not query languages and list no keywords.
#[must_use]
pub const fn keywords(language: LanguageId) -> Option<Keywords> {
    match language {
        LanguageId::Kql => kql::KEYWORDS,
        LanguageId::Spl => spl::KEYWORDS,
        LanguageId::Esql => esql::KEYWORDS,
        LanguageId::Eql => eql::KEYWORDS,
        LanguageId::Kuery => kuery::KEYWORDS,
        LanguageId::Lucene => lucene::KEYWORDS,
        LanguageId::Falco => falco::KEYWORDS,
        LanguageId::Cql => cql::KEYWORDS,
        LanguageId::Yara => yara::KEYWORDS,
        LanguageId::Exabeam => exabeam::KEYWORDS,
        LanguageId::Yaral => yaral::KEYWORDS,
        LanguageId::Datadog => datadog::KEYWORDS,
        // Not query languages: no keywords of their own.
        LanguageId::TideYaml | LanguageId::Config => None,
    }
}

/// `(token, capture name)` pairs of a table.
pub(crate) fn table_pairs(table: &[(&str, Capture)]) -> Vec<(String, String)> {
    table
        .iter()
        .map(|(token, capture)| ((*token).to_string(), capture.name().to_string()))
        .collect()
}

/// The pairs of `language`: its table, or none.
pub(crate) fn language_pairs(language: LanguageId) -> Vec<(String, String)> {
    keywords(language).map(table_pairs).unwrap_or_default()
}

/// The tokens of each capture, sorted and without duplicates.
pub(crate) fn by_capture(pairs: Vec<(String, String)>) -> BTreeMap<String, BTreeSet<String>> {
    let mut by_capture: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (token, capture) in pairs {
        by_capture.entry(capture).or_default().insert(token);
    }
    by_capture
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HighlightSpec, generate_tm_language, generate_tm_language_from};

    const ALL: [LanguageId; 14] = [
        LanguageId::Kql,
        LanguageId::Spl,
        LanguageId::TideYaml,
        LanguageId::Esql,
        LanguageId::Eql,
        LanguageId::Kuery,
        LanguageId::Lucene,
        LanguageId::Config,
        LanguageId::Falco,
        LanguageId::Cql,
        LanguageId::Yara,
        LanguageId::Exabeam,
        LanguageId::Yaral,
        LanguageId::Datadog,
    ];

    #[test]
    fn a_table_is_grouped_and_ordered_by_capture() {
        // The order of the table and repeated rows do not change the output.
        let spec = HighlightSpec::load().expect("spec");
        let mut table = keywords(LanguageId::Kql).expect("a KQL table").to_vec();
        let forward = generate_tm_language_from(LanguageId::Kql, &spec, table_pairs(&table));
        assert_eq!(forward, generate_tm_language(LanguageId::Kql, &spec));
        table.reverse();
        let doubled: Vec<_> = table.iter().chain(table.iter()).copied().collect();
        let reversed = generate_tm_language_from(LanguageId::Kql, &spec, table_pairs(&doubled));
        assert_eq!(forward, reversed);
        assert!(
            forward["patterns"]
                .as_array()
                .is_some_and(|p| p.iter().any(|v| v["comment"] == "capture:keyword")),
            "the KQL grammar has keyword patterns"
        );
    }

    #[test]
    fn every_query_language_has_a_table_and_the_others_none() {
        let spec = HighlightSpec::load().expect("spec");
        for language in ALL {
            let query = LanguageId::QUERY_LANGUAGES.contains(&language);
            assert_eq!(keywords(language).is_some(), query, "{language}");
            if !query {
                assert_eq!(
                    generate_tm_language(language, &spec),
                    generate_tm_language_from(language, &spec, Vec::new()),
                    "{language}"
                );
            }
        }
    }

    #[test]
    fn capture_constants_name_spec_captures() {
        let spec = HighlightSpec::load().expect("spec");
        for capture in [
            Capture::COMMENT,
            Capture::KEYWORD,
            Capture::OPERATOR,
            Capture::PIPE,
            Capture::FUNCTION,
            Capture::FUNCTION_BUILTIN,
            Capture::TYPE,
            Capture::VARIABLE,
            Capture::PROPERTY,
            Capture::STRING,
            Capture::NUMBER,
            Capture::BOOLEAN,
            Capture::CONSTANT,
            Capture::PUNCTUATION,
            Capture::BRACKET,
            Capture::DELIMITER,
            Capture::ERROR,
            Capture::MACRO,
        ] {
            assert!(
                spec.contains_capture(capture.name()),
                "{} is not a capture of highlights/spec.toml",
                capture.name()
            );
        }
    }

    #[test]
    fn keyword_tables_name_spec_captures() {
        // The tables are static data in this crate, so this test is their
        // guard: it runs on every change to the crate, and a table that
        // names a capture the spec lacks (which the generator would skip)
        // or an empty token (which would
        // generate an empty pattern) fails it.
        let spec = HighlightSpec::load().expect("spec");
        for language in ALL {
            for (token, capture) in keywords(language).unwrap_or_default() {
                assert!(!token.is_empty(), "{language}: an empty token");
                assert!(
                    spec.contains_capture(capture.name()),
                    "{language}: `{token}` names {}, which highlights/spec.toml does not have",
                    capture.name()
                );
            }
        }
    }
}
