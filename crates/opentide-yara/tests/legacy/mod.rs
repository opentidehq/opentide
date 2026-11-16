//! The tree-sitter engine's highlighting, folding and parenthesis pairs, as
//! they were before the CST (#1225): the oracle of `cst_differential.rs`,
//! deleted with it.

#![expect(clippy::expect_used, reason = "test oracle: a panic fails the test")]

use opentide_core::{ByteSpan, LanguageId};
use opentide_highlight::{HighlightSpec, HighlightToken, YARA_HIGHLIGHTS_SCM, tokens_from_spans};

pub fn highlight(source: &str) -> Vec<HighlightToken> {
    let spec = HighlightSpec::load().expect("spec");
    let Ok(spans) = opentide_syntax::query_captures(LanguageId::Yara, source, YARA_HIGHLIGHTS_SCM)
    else {
        return Vec::new();
    };
    let spans: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(&spec, source, &spans).unwrap_or_default()
}

pub fn has_error(source: &str) -> bool {
    opentide_syntax::parse(LanguageId::Yara, source).is_none_or(|t| t.root_node().has_error())
}

pub fn paren_pairs(source: &str) -> Vec<(usize, usize)> {
    let mut pairs = Vec::new();
    let Some(tree) = opentide_syntax::parse(LanguageId::Yara, source) else {
        return pairs;
    };
    let mut open: Vec<usize> = Vec::new();
    let mut cursor = tree.walk();
    'walk: loop {
        let node = cursor.node();
        if node.child_count() == 0 && !node.is_missing() {
            match node.kind() {
                "(" => open.push(node.start_byte()),
                ")" => {
                    if let Some(o) = open.pop() {
                        pairs.push((o, node.start_byte()));
                    }
                }
                _ => {}
            }
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                break 'walk;
            }
        }
    }
    pairs
}

pub fn folding(source: &str) -> Vec<(usize, usize)> {
    let Some(tree) = opentide_syntax::parse(LanguageId::Yara, source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "rule"
                | "meta_section"
                | "strings_section"
                | "condition_section"
                | "hex_string"
                | "comment"
        ) && node.start_position().row < node.end_position().row
        {
            out.push((node.start_byte(), node.end_byte()));
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    out.sort_unstable();
    out
}
