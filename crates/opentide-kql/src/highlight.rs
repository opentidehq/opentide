//! Highlighting on the new tree: `capture(token, parent)` gives each token the
//! `HighlightSpec` capture `highlights.scm` gave it, so semantic tokens do not
//! change (#1230). The capture names are a frozen contract.
//!
//! The rules read as the `.scm` did. A keyword is coloured where its parent
//! says so ([`PARENT_RULES`]: `(where_operator "where" @keyword)`), a few
//! words anywhere ([`global`]), and a name by where it stands: a call, a
//! type, a member, a table, a variable.

use crate::syntax::{SyntaxElement, SyntaxKind as K, SyntaxToken};
use opentide_core::ByteSpan;
use rowan::NodeOrToken;

/// `(parent, keyword, capture)`: the keyword is coloured only under that parent.
#[rustfmt::skip]
const PARENT_RULES: &[(K, K, &str)] = &[
    (K::LET_STATEMENT, K::LET_KW, "keyword"),
    (K::COUNT_OPERATOR, K::COUNT_KW, "keyword"),
    (K::WHERE_OPERATOR, K::WHERE_KW, "keyword"),
    (K::FILTER_OPERATOR, K::FILTER_KW, "keyword"),
    (K::PROJECT_OPERATOR, K::PROJECT_KW, "keyword"),
    (K::PROJECT_AWAY_OPERATOR, K::PROJECT_AWAY_KW, "keyword"),
    (K::PROJECT_RENAME_OPERATOR, K::PROJECT_RENAME_KW, "keyword"),
    (K::PROJECT_KEEP_OPERATOR, K::PROJECT_KEEP_KW, "keyword"),
    (K::PROJECT_REORDER_OPERATOR, K::PROJECT_REORDER_KW, "keyword"),
    (K::EXTEND_OPERATOR, K::EXTEND_KW, "keyword"),
    (K::SUMMARIZE_OPERATOR, K::SUMMARIZE_KW, "keyword"),
    (K::JOIN_OPERATOR, K::JOIN_KW, "keyword"),
    (K::UNION_OPERATOR, K::UNION_KW, "keyword"),
    (K::PARSE_OPERATOR, K::PARSE_KW, "keyword"),
    (K::PARSE_WHERE_OPERATOR, K::PARSE_WHERE_KW, "keyword"),
    (K::PARSE_KV_OPERATOR, K::PARSE_KV_KW, "keyword"),
    (K::LOOKUP_OPERATOR, K::LOOKUP_KW, "keyword"),
    (K::TAKE_OPERATOR, K::TAKE_KW, "keyword"),
    (K::LIMIT_OPERATOR, K::LIMIT_KW, "keyword"),
    (K::SORT_OPERATOR, K::SORT_KW, "keyword"),
    (K::SORT_OPERATOR, K::ORDER_KW, "keyword"),
    (K::DISTINCT_OPERATOR, K::DISTINCT_KW, "keyword"),
    (K::RENDER_OPERATOR, K::RENDER_KW, "keyword"),
    (K::PRINT_OPERATOR, K::PRINT_KW, "keyword"),
    (K::TOP_OPERATOR, K::TOP_KW, "keyword"),
    (K::MV_EXPAND_OPERATOR, K::MV_EXPAND_KW, "keyword"),
    (K::MV_EXPAND_OPERATOR, K::MVEXPAND_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::SEARCH_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::FIND_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::INVOKE_KW, "keyword"),
    (K::EVALUATE_OPERATOR, K::EVALUATE_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::SERIALIZE_KW, "keyword"),
    (K::SCAN_OPERATOR, K::SCAN_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::AS_KW, "keyword"),
    (K::PARSE_KV_OPERATOR, K::AS_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::GETSCHEMA_KW, "keyword"),
    (K::MAKE_SERIES_OPERATOR, K::MAKE_SERIES_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::SAMPLE_KW, "keyword"),
    (K::SAMPLE_DISTINCT_OPERATOR, K::SAMPLE_DISTINCT_KW, "keyword"),
    (K::MV_APPLY_OPERATOR, K::MV_APPLY_KW, "keyword"),
    (K::DATATABLE_EXPRESSION, K::DATATABLE_KW, "keyword"),
    (K::EXTERNALDATA_EXPRESSION, K::EXTERNALDATA_KW, "keyword"),
    (K::EXTERNALDATA_EXPRESSION, K::EXTERNAL_DATA_KW, "keyword"),
    (K::EXTERNALDATA_EXPRESSION, K::WITH_KW, "keyword"),
    (K::RANGE_OPERATOR, K::FROM_KW, "keyword"),
    (K::RANGE_OPERATOR, K::TO_KW, "keyword"),
    (K::RANGE_OPERATOR, K::STEP_KW, "keyword"),
    (K::REORDER_ITEM, K::ASC_KW, "keyword"),
    (K::REORDER_ITEM, K::DESC_KW, "keyword"),
    (K::REORDER_ITEM, K::GRANNY_ASC_KW, "keyword"),
    (K::REORDER_ITEM, K::GRANNY_DESC_KW, "keyword"),
    (K::TOP_NESTED_OF, K::OF_KW, "keyword"),
    (K::TOP_NESTED_OTHERS, K::WITH_KW, "keyword"),
    (K::TOP_NESTED_OTHERS, K::OTHERS_KW, "keyword"),
    (K::TOP_NESTED_BY, K::BY_KW, "keyword"),
    (K::SAMPLE_DISTINCT_OPERATOR, K::OF_KW, "keyword"),
    (K::FACET_OPERATOR, K::BY_KW, "keyword"),
    (K::FACET_OPERATOR, K::WITH_KW, "keyword"),
    (K::PARTITION_OPERATOR, K::BY_KW, "keyword"),
    (K::SCAN_OPERATOR, K::ORDER_KW, "keyword"),
    (K::SCAN_OPERATOR, K::PARTITION_KW, "keyword"),
    (K::SCAN_OPERATOR, K::BY_KW, "keyword"),
    (K::SCAN_OPERATOR, K::DECLARE_KW, "keyword"),
    (K::SCAN_OPERATOR, K::WITH_KW, "keyword"),
    (K::SCAN_STEP, K::STEP_KW, "keyword"),
    (K::SCAN_STEP, K::OPTIONAL_KW, "keyword"),
    (K::SCAN_STEP, K::OUTPUT_KW, "keyword"),
    (K::SCAN_STEP, K::LAST_KW, "keyword"),
    (K::RANGE_OPERATOR, K::RANGE_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::EXTERNALDATA_KW, "keyword"),
    (K::PARTITION_OPERATOR, K::PARTITION_KW, "keyword"),
    (K::FORK_OPERATOR, K::FORK_KW, "keyword"),
    (K::FACET_OPERATOR, K::FACET_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::CONSUME_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::REDUCE_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::MAKE_GRAPH_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::GRAPH_MATCH_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::GRAPH_SHORTEST_PATHS_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::GRAPH_TO_TABLE_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::GRAPH_MARK_COMPONENTS_KW, "keyword"),
    (K::KEYWORD_OPERATOR, K::TOP_HITTERS_KW, "keyword"),
    (K::TOP_NESTED_CLAUSE, K::TOP_NESTED_KW, "keyword"),
    (K::MV_EXPAND_OPERATOR, K::LIMIT_KW, "keyword"),
    (K::MV_EXPAND_ITEM, K::TO_KW, "keyword"),
    (K::MV_EXPAND_ITEM, K::TYPEOF_KW, "keyword"),
    (K::MV_APPLY_OPERATOR, K::ON_KW, "keyword"),
    (K::MAKE_SERIES_OPERATOR, K::ON_KW, "keyword"),
    (K::MAKE_SERIES_OPERATOR, K::FROM_KW, "keyword"),
    (K::MAKE_SERIES_OPERATOR, K::TO_KW, "keyword"),
    (K::MAKE_SERIES_OPERATOR, K::STEP_KW, "keyword"),
    (K::MAKE_SERIES_OPERATOR, K::BY_KW, "keyword"),
    (K::SORT_ITEM, K::NULLS_KW, "keyword"),
    (K::SORT_ITEM, K::FIRST_KW, "keyword"),
    (K::SORT_ITEM, K::LAST_KW, "keyword"),
    (K::SERIES_DEFAULT, K::DEFAULT_KW, "keyword"),
    (K::MATERIALIZE_EXPRESSION, K::MATERIALIZE_KW, "function.builtin"),
    (K::TOSCALAR_EXPR, K::TOSCALAR_KW, "function.builtin"),
    (K::DYNAMIC_LITERAL, K::DYNAMIC_KW, "type"),
    (K::TYPE, K::DYNAMIC_KW, "type"),
    (K::CONTROL_COMMAND, K::DOT, "error"),
];

/// The capture of a token wherever it stands: operators, brackets, a few
/// keywords.
fn global(kind: K) -> Option<&'static str> {
    Some(match kind {
        K::PIPE => "operator.pipe",
        K::AND_KW | K::BY_KW | K::ON_KW | K::WITH_KW | K::KIND_KW | K::ASC_KW | K::DESC_KW => {
            "keyword"
        }
        K::OR_KW
        | K::NOT_KW
        | K::CMP_OP
        | K::SET_OP
        | K::BETWEEN_OP
        | K::IN_KW
        | K::MATCHES_KW
        | K::REGEX_KW
        | K::EQ
        | K::FAT_ARROW
        | K::DOT_DOT
        | K::PLUS
        | K::MINUS
        | K::STAR
        | K::SLASH
        | K::PERCENT => "operator",
        K::L_PAREN | K::R_PAREN | K::L_BRACKET | K::R_BRACKET | K::L_BRACE | K::R_BRACE => {
            "punctuation.bracket"
        }
        K::COMMA | K::SEMICOLON => "punctuation.delimiter",
        _ => return None,
    })
}

/// The capture of `token` under `parent`, or none.
///
/// A column pattern (`User*`) is several tokens here and one in the old
/// grammar; [`highlight_span`] colours it as one span and never asks.
pub(crate) fn capture(token: &SyntaxToken, parent: K) -> Option<&'static str> {
    let kind = token.kind();
    if let Some((_, _, capture)) = PARENT_RULES
        .iter()
        .find(|(p, k, _)| *p == parent && *k == kind)
    {
        return Some(capture);
    }
    // Names that are keywords of an option: `kind=inner`, `hint.strategy=x`.
    let first_token = || {
        token
            .parent()
            .and_then(|p| p.children_with_tokens().find_map(NodeOrToken::into_token))
            .is_some_and(|t| &t == token)
    };
    match (parent, kind) {
        (K::OPERATOR_OPTION | K::MV_OPTION | K::HINT_OPTION, _) if first_token() => {
            return Some("keyword");
        }
        (K::CONTROL_COMMAND, K::DOT | K::IDENT) => return Some("error"),
        (K::MEMBER_EXPR, K::IDENT) => return Some("property"),
        (K::FUNCTION_CALL, K::IDENT) => return Some("function"),
        (K::TYPE | K::TABLE_COLUMN, K::IDENT) => return Some("type"),
        (K::TABLE_REF, K::IDENT) => {
            let in_union = token
                .parent()
                .and_then(|p| p.parent())
                .is_some_and(|g| g.kind() == K::UNION_OPERATOR);
            return Some(if in_union { "variable" } else { "type" });
        }
        _ => {}
    }
    match kind {
        K::COMMENT => Some("comment"),
        K::STRING => Some("string"),
        K::NUMBER | K::TIMESPAN => Some("number"),
        K::BOOLEAN => Some("boolean"),
        K::NULL_KW => Some("constant"),
        K::TYPED_LITERAL => Some("constant"),
        K::IDENT | K::QUOTED_IDENT => Some("variable"),
        _ => global(kind),
    }
}

/// The `(span, capture)` of every coloured token of the tree, in order. The
/// captures are the spec's names, borrowed: a copy per token was a few
/// percent of a query's analysis.
#[cfg(test)]
pub(crate) fn highlight_spans(root: &crate::syntax::SyntaxNode) -> Vec<(ByteSpan, &'static str)> {
    let mut out = Vec::new();
    for element in root.descendants_with_tokens() {
        highlight_span(&element, &mut out);
    }
    out
}

/// `highlight_spans` one element at a time, in preorder, as
/// `opentide_parse::walk_once` gives them (ADR 0014 §5a: the analysis walks
/// its tree once, and the highlight reads that walk as it goes).
pub(crate) fn highlight_span(element: &SyntaxElement, out: &mut Vec<(ByteSpan, &'static str)>) {
    match element {
        NodeOrToken::Node(node) if node.kind() == K::COLUMN_PATTERN => {
            let range = node.text_range();
            out.push((
                ByteSpan::new(usize::from(range.start()), usize::from(range.end())),
                "variable",
            ));
        }
        NodeOrToken::Token(token) => {
            let Some(parent) = token.parent() else {
                return;
            };
            if parent.kind() == K::COLUMN_PATTERN {
                return;
            }
            if let Some(capture) = capture(token, parent.kind()) {
                let range = token.text_range();
                if !range.is_empty() {
                    out.push((
                        ByteSpan::new(usize::from(range.start()), usize::from(range.end())),
                        capture,
                    ));
                }
            }
        }
        NodeOrToken::Node(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;
    use crate::syntax::SyntaxNode;

    fn captures(source: &str) -> Vec<(&str, &'static str)> {
        let root = SyntaxNode::new_root(parse(source).green);
        highlight_spans(&root)
            .into_iter()
            .map(|(span, capture)| (&source[span.start..span.end], capture))
            .collect()
    }

    #[test]
    fn a_keyword_is_coloured_where_its_parent_takes_it() {
        let got = captures("T | where count > 1 | count | project-away User*");
        let find = |text: &str| {
            got.iter()
                .filter(|(t, _)| *t == text)
                .map(|(_, c)| *c)
                .collect::<Vec<_>>()
        };
        assert_eq!(find("T"), ["type"]);
        assert_eq!(find("where"), ["keyword"]);
        // `count` is a column in the predicate and the operator after the pipe.
        assert_eq!(find("count"), ["variable", "keyword"]);
        assert_eq!(
            find("|"),
            ["operator.pipe", "operator.pipe", "operator.pipe"]
        );
        assert_eq!(find("User*"), ["variable"], "a column pattern is one span");
    }

    #[test]
    fn names_take_the_capture_of_where_they_stand() {
        let got = captures(
            "let f = (t: (*), n: int) { t };\nf(T, 1) | extend x = d.k, y = strlen(\"a\") | union U",
        );
        let find = |text: &str| got.iter().find(|(t, _)| *t == text).map(|(_, c)| *c);
        assert_eq!(find("int"), Some("type"));
        assert_eq!(find("strlen"), Some("function"));
        assert_eq!(find("k"), Some("property"));
        assert_eq!(find("U"), Some("variable"), "a union leg");
        assert_eq!(find("\"a\""), Some("string"));
    }
}
