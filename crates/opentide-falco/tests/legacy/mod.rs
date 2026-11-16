//! The tree-sitter implementation of Falco's highlighting and fields, copied
//! verbatim from `src/lib.rs` (`highlight`'s query and `fields`), for the
//! differential until the series' last PR deletes it with the grammar.

use opentide_core::{ByteSpan, LanguageId};
use std::collections::BTreeSet;

/// The spans of `text` the highlight query captures, resolved so that none
/// overlaps (`opentide_syntax::query_captures`).
pub fn captures(text: &str) -> Vec<(ByteSpan, String)> {
    opentide_syntax::query_captures(
        LanguageId::Falco,
        text,
        opentide_highlight::FALCO_HIGHLIGHTS_SCM,
    )
    .unwrap_or_default()
}

/// Every field a condition mentions, in source order, deduplicated.
pub fn fields(text: &str) -> Vec<String> {
    let Some(tree) = opentide_syntax::parse(LanguageId::Falco, text) else {
        return Vec::new();
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    opentide_syntax::walk_with_ancestors(tree.root_node(), |node, _| {
        if node.kind() == "field_name" {
            let name = text
                .get(node.start_byte()..node.end_byte())
                .unwrap_or("")
                .to_string();
            if seen.insert(name.clone()) {
                out.push(name);
            }
        }
    });
    out
}

/// Whether tree-sitter parses `text` with no error node.
pub fn has_error(text: &str) -> bool {
    opentide_syntax::parse(LanguageId::Falco, text)
        .is_none_or(|tree| opentide_syntax::has_error(&tree))
}
