//! Highlighting from the tree: a capture for each token, by its kind and its
//! parent. The capture names are the frozen contract of `highlights/spec.toml`;
//! the keywords and punctuation are the `KEYWORDS` table of `opentide-highlight`.

use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use opentide_core::{ByteSpan, LanguageId};
use opentide_highlight::{HighlightSpec, HighlightToken, keywords, tokens_from_spans};
use rowan::NodeOrToken;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Outcomes Google gives a meaning: constants, before every other variable.
fn platform_outcome(name: &str) -> bool {
    matches!(name, "$risk_score" | "$suppression_key")
        || name
            .strip_prefix("$risk_entity_to_score")
            .is_some_and(|rest| {
                rest.is_empty()
                    || rest.strip_prefix('_').is_some_and(|r| {
                        !r.is_empty() && r.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    })
            })
}

/// The capture of `token`, whose parent is `parent`.
fn capture(token: &SyntaxToken, parent: Option<K>) -> Option<&'static str> {
    let kind = token.kind();
    Some(match kind {
        K::COMMENT => "comment",
        K::IDENT => match parent? {
            K::RULE_NAME | K::STAGE_NAME => "type",
            K::META_KEY
            | K::OPTION_KEY
            | K::ARGUMENT_NAME
            | K::NAME_REF
            | K::BARE_FIELD
            | K::DATA_TABLE_COLUMN => "property",
            K::TIME_UNIT => "keyword",
            K::TABLE_CALL => "function.builtin",
            K::FUNCTION_NAME => {
                // `strings` of `strings.to_lower` is a type; a lone name is the function.
                if token
                    .next_sibling_or_token()
                    .is_some_and(|s| s.kind() == K::ACCESS_DOT)
                {
                    "type"
                } else {
                    "function.builtin"
                }
            }
            _ => return None,
        },
        K::FIELD_NAME => match parent? {
            K::MEMBER => "property",
            K::FUNCTION_NAME => "function.builtin",
            _ => return None,
        },
        K::VAR_TOKEN => {
            if platform_outcome(token.text()) {
                "constant"
            } else {
                "variable"
            }
        }
        K::COUNT_TOKEN => "variable",
        K::REF_LIST_TOKEN | K::WINDOW_START_KW | K::WINDOW_END_KW => "constant",
        K::STRING | K::RAW_STRING | K::REGEX_LIT => "string",
        K::INTEGER | K::FLOAT | K::DURATION => "number",
        K::TRUE_KW | K::FALSE_KW => "boolean",
        _ => {
            let text = token.text();
            let table = keyword_captures()?;
            return if text.bytes().any(|b| b.is_ascii_uppercase()) {
                table.get(text.to_ascii_lowercase().as_str()).copied()
            } else {
                table.get(text).copied()
            };
        }
    })
}

/// The capture of each text of the `KEYWORDS` table, built once: a scan of
/// the table per token was a share of the highlight (ADR 0014 §2). The
/// table's first row for a text wins, as the scan's did.
fn keyword_captures() -> Option<&'static HashMap<&'static str, &'static str>> {
    static CAPTURES: OnceLock<Option<HashMap<&'static str, &'static str>>> = OnceLock::new();
    CAPTURES
        .get_or_init(|| {
            let table = keywords(LanguageId::Yaral)?;
            let mut captures = HashMap::new();
            for (text, capture) in table {
                captures.entry(*text).or_insert(capture.name());
            }
            Some(captures)
        })
        .as_ref()
}

/// The highlight's span of `token` and its capture, if it has one.
pub(crate) fn span(token: &SyntaxToken) -> Option<(ByteSpan, &'static str)> {
    if token.kind() == K::WHITESPACE || token.text().is_empty() {
        return None;
    }
    let parent = token.parent().map(|p| p.kind());
    let capture = capture(token, parent)?;
    let range = token.text_range();
    Some((
        ByteSpan::new(usize::from(range.start()), usize::from(range.end())),
        capture,
    ))
}

/// The semantic tokens of `spans`, in document order.
pub(crate) fn tokens(spans: &[(ByteSpan, &'static str)], source: &str) -> Vec<HighlightToken> {
    let Ok(spec) = HighlightSpec::shared() else {
        return Vec::new();
    };
    tokens_from_spans(spec, source, spans).unwrap_or_default()
}

/// Semantic tokens of the tree.
pub(crate) fn highlight(root: &SyntaxNode, source: &str) -> Vec<HighlightToken> {
    let spans: Vec<(ByteSpan, &'static str)> = root
        .descendants_with_tokens()
        .inspect(|_| super::count_visit())
        .filter_map(NodeOrToken::into_token)
        .filter_map(|t| span(&t))
        .collect();
    tokens(&spans, source)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keyword index finds what a scan of the table finds, for each text
    /// of the table in each case (ADR 0014 §2).
    #[test]
    fn the_keyword_index_finds_what_a_scan_finds() {
        let table = keywords(LanguageId::Yaral).unwrap_or_default();
        assert!(!table.is_empty());
        let index = keyword_captures().expect("the YARA-L keyword table");
        for (text, _) in table {
            for probe in [
                text.to_string(),
                text.to_ascii_uppercase(),
                format!("{text}x"),
            ] {
                let lower = probe.to_ascii_lowercase();
                let scanned = table
                    .iter()
                    .find(|(t, _)| *t == lower)
                    .map(|(_, c)| c.name());
                let found = if probe.bytes().any(|b| b.is_ascii_uppercase()) {
                    index.get(lower.as_str()).copied()
                } else {
                    index.get(probe.as_str()).copied()
                };
                assert_eq!(found, scanned, "{probe:?}");
            }
        }
    }
}
