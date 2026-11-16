//! Highlighting from the tree: a capture for each token, by its kind and its
//! parent. The capture names are the frozen contract of `highlights/spec.toml`;
//! the keywords and punctuation are the `KEYWORDS` table of `opentide-highlight`.

use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use opentide_core::{ByteSpan, LanguageId};
use opentide_highlight::{HighlightSpec, HighlightToken, keywords, tokens_from_spans};
use rowan::NodeOrToken;

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
            let table = keywords(LanguageId::Yaral)?;
            let text = token.text().to_ascii_lowercase();
            return table
                .iter()
                .find(|(t, _)| *t == text)
                .map(|(_, c)| c.name());
        }
    })
}

/// Semantic tokens of the tree.
pub(crate) fn highlight(root: &SyntaxNode, source: &str) -> Vec<HighlightToken> {
    let Ok(spec) = HighlightSpec::load() else {
        return Vec::new();
    };
    let mut spans: Vec<(ByteSpan, &'static str)> = Vec::new();
    for element in root.descendants_with_tokens() {
        let NodeOrToken::Token(token) = element else {
            continue;
        };
        if token.kind() == K::WHITESPACE || token.text().is_empty() {
            continue;
        }
        let parent = token.parent().map(|p| p.kind());
        if let Some(capture) = capture(&token, parent) {
            let range = token.text_range();
            spans.push((
                ByteSpan::new(usize::from(range.start()), usize::from(range.end())),
                capture,
            ));
        }
    }
    tokens_from_spans(&spec, source, &spans).unwrap_or_default()
}
