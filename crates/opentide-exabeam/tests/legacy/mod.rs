//! The tree-sitter implementation of Exabeam's highlighting, copied verbatim
//! from `src/lib.rs` (`highlight`'s query), for the differential until it is
//! deleted with the grammar.

use opentide_core::{ByteSpan, LanguageId};

/// The spans of `text` the highlight query captures, resolved so that none
/// overlaps (`opentide_syntax::query_captures`).
pub fn captures(text: &str) -> Vec<(ByteSpan, String)> {
    opentide_syntax::query_captures(
        LanguageId::Exabeam,
        text,
        opentide_highlight::EXABEAM_HIGHLIGHTS_SCM,
    )
    .unwrap_or_default()
}

/// Whether tree-sitter parses `text` with no error node.
pub fn has_error(text: &str) -> bool {
    opentide_syntax::parse(LanguageId::Exabeam, text)
        .is_none_or(|tree| opentide_syntax::has_error(&tree))
}
