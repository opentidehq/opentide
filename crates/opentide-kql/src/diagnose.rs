//! The diagnostics that read the tree, on the new parser (#1230): the syntax
//! error, control commands, unknown and `render` operators, functions,
//! legacy scalar operators and tables, and the highlight tokens. The column
//! pass (`schema`) and the performance checks (`perf`) are still on
//! tree-sitter; the analysis port moves them next.

use crate::highlight::highlight_spans;
use crate::parser::parse;
use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use crate::{Catalog, TYPED_LITERAL_TYPES, check_table_named, overlay_catalog_captures};
use opentide_core::{ByteSpan, Diagnostic, Range, codes, span_to_range, suggest};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_parse::SyntaxError;
use rowan::NodeOrToken;
use std::collections::BTreeSet;

/// What the new parser gives so far.
pub(crate) struct Analysis {
    /// The diagnostics that read the tree, in the old order.
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) tokens: Vec<HighlightToken>,
}

/// The tree-reading part of `analyze_with_catalog`.
#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
pub(crate) fn analyze(source: &str, catalog: &Catalog) -> Analysis {
    let parsed = parse(source);
    let root = SyntaxNode::new_root(parsed.green);
    let mut diagnostics = Vec::new();
    if let Some(error) = parsed.errors.first() {
        diagnostics.push(syntax_error(source, &root, error));
    }
    control_commands(&root, source, &mut diagnostics);
    operators(&root, source, catalog, &mut diagnostics);
    let lets = let_names(&root);
    functions(&root, source, catalog, &lets, &mut diagnostics);
    scalar_operators(&root, source, catalog, &mut diagnostics);
    tables(&root, source, catalog, &lets, &mut diagnostics);
    let spec = HighlightSpec::load().expect("highlight spec");
    let mut spans = highlight_spans(&root);
    overlay_catalog_captures(source, &mut spans, catalog);
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    let tokens = tokens_from_spans(&spec, source, &refs).unwrap_or_default();
    Analysis {
        diagnostics,
        tokens,
    }
}

/// The range of a node or token, at least one byte wide.
fn range_of(source: &str, range: rowan::TextRange) -> Range {
    let start = usize::from(range.start());
    span_to_range(
        source,
        ByteSpan::new(start, usize::from(range.end()).max(start + 1)),
    )
}

/// The first identifier token directly under `node`: the name of a call, a
/// `let`, a parameter, an unknown operator.
fn name_of(node: &SyntaxNode) -> Option<SyntaxToken> {
    node.children_with_tokens()
        .filter_map(NodeOrToken::into_token)
        .find(|t| t.kind() == K::IDENT)
}

/// `expected a, b, or c` of a set of kinds.
fn expected_phrase(error: &SyntaxError) -> Option<String> {
    let mut names: Vec<String> = Vec::new();
    for kind in error.expected.iter() {
        let name = K::from_raw(kind).describe();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let (last, rest) = names.split_last()?;
    Some(if rest.is_empty() {
        last.clone()
    } else {
        format!("{}, or {last}", rest.join(", "))
    })
}

/// The one syntax error the old engine reported, with what the parser
/// expected: at the token the error stands before.
fn syntax_error(source: &str, root: &SyntaxNode, error: &SyntaxError) -> Diagnostic {
    let mut message = format!("KQL syntax error: {}", error.message);
    if !error.message.starts_with("expected")
        && let Some(expected) = expected_phrase(error)
    {
        message.push_str(&format!("; expected {expected}"));
    }
    let at = error.gap.end();
    let mut next = root.token_at_offset(at).right_biased();
    while let Some(token) = &next {
        if !matches!(token.kind(), K::WHITESPACE | K::COMMENT) && token.text_range().start() >= at {
            break;
        }
        next = token.next_token();
    }
    // Past the last token, the error is on that token: an empty range at the end
    // of the text, often a blank line, is not visible in an editor.
    let range = next
        .or_else(|| {
            // Not `last_token`: it stops at an empty last node.
            root.descendants_with_tokens()
                .filter_map(NodeOrToken::into_token)
                .filter(|t| !matches!(t.kind(), K::WHITESPACE | K::COMMENT))
                .last()
        })
        .map_or_else(|| rowan::TextRange::empty(at), |t| t.text_range());
    Diagnostic::error(codes::KQL_PARSE_ERROR, message, range_of(source, range))
}

/// `.show tables`: reported once.
fn control_commands(root: &SyntaxNode, source: &str, out: &mut Vec<Diagnostic>) {
    if let Some(node) = root.descendants().find(|n| n.kind() == K::CONTROL_COMMAND) {
        let name = name_of(&node).map_or_else(|| ".".into(), |t| t.text().to_owned());
        out.push(Diagnostic::error(
            codes::KQL_CONTROL_COMMAND_UNSUPPORTED,
            format!("KQL control command '.{name}' is not valid in detections"),
            range_of(source, node.text_range()),
        ));
    }
}

/// Unknown operators, and `render`.
fn operators(root: &SyntaxNode, source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    for node in root.descendants() {
        match node.kind() {
            K::UNKNOWN_OPERATOR => {
                let name = name_of(&node)
                    .map(|t| t.text().to_owned())
                    .unwrap_or_default();
                if catalog.operator(&name).is_none() {
                    let mut d = Diagnostic::error(
                        codes::KQL_UNKNOWN_OPERATOR,
                        format!("unknown tabular operator '{name}'"),
                        range_of(source, node.text_range()),
                    );
                    if let Some(s) =
                        suggest::closest(&name, catalog.operators.iter().map(|o| o.name.as_str()))
                    {
                        d = d.with_suggestion(s);
                    }
                    out.push(d);
                }
            }
            K::RENDER_OPERATOR => out.push(Diagnostic::warning(
                codes::KQL_RENDER_NOT_VALID,
                "`render` is not valid in detection queries",
                range_of(source, node.text_range()),
            )),
            _ => {}
        }
    }
}

/// Names bound by `let` anywhere in the query.
fn let_names(root: &SyntaxNode) -> BTreeSet<String> {
    root.descendants()
        .filter(|n| n.kind() == K::LET_STATEMENT)
        .filter_map(|n| name_of(&n).map(|t| t.text().to_owned()))
        .collect()
}

/// Calls: typed literals written as calls, plugins, deprecated and
/// misspelled functions.
fn functions(
    root: &SyntaxNode,
    source: &str,
    catalog: &Catalog,
    lets: &BTreeSet<String>,
    out: &mut Vec<Diagnostic>,
) {
    for node in root.descendants().filter(|n| n.kind() == K::FUNCTION_CALL) {
        let Some(name_token) = name_of(&node) else {
            continue;
        };
        let name = name_token.text().to_owned();
        let name_range = range_of(source, name_token.text_range());
        let is_plugin = node
            .parent()
            .is_some_and(|p| p.kind() == K::EVALUATE_OPERATOR);
        let function = catalog.function(&name);
        if lets.contains(&name) {
            // A function the query declares with `let`.
        } else if !is_plugin && TYPED_LITERAL_TYPES.contains(&name.as_str()) {
            out.push(Diagnostic::error(
                codes::KQL_PARSE_ERROR,
                format!(
                    "'{name}(' starts a typed literal: write the value and ')' on the same line, directly after '{name}'"
                ),
                range_of(source, node.text_range()),
            ));
        } else if is_plugin {
            if catalog.plugin(&name).is_none() {
                let mut d = Diagnostic::error(
                    codes::KQL_UNKNOWN_FUNCTION,
                    format!("unknown evaluate plugin '{name}'"),
                    name_range,
                );
                if let Some(s) =
                    suggest::closest(&name, catalog.plugins.iter().map(|p| p.name.as_str()))
                {
                    d = d.with_suggestion(s);
                }
                out.push(d);
            }
        } else if let Some(replacement) = function.and_then(|f| f.deprecated.as_ref()) {
            out.push(
                Diagnostic::warning(
                    codes::KQL_DEPRECATED_FUNCTION,
                    format!("'{name}' is deprecated; use {replacement}()"),
                    name_range,
                )
                .with_suggestion(replacement.clone()),
            );
        } else if function.is_none() && catalog.operator(&name).is_none() {
            // Only a likely typo of a known function: within two edits.
            if let Some(suggestion) = suggest::best(
                &name,
                catalog
                    .functions
                    .iter()
                    .filter(|f| f.deprecated.is_none())
                    .map(|f| f.name.as_str())
                    .filter(|f| (1..=2).contains(&strsim::levenshtein(f, &name))),
            ) {
                out.push(
                    Diagnostic::error(
                        codes::KQL_UNKNOWN_FUNCTION,
                        format!("unknown function '{name}'"),
                        name_range,
                    )
                    .with_suggestion(suggestion),
                );
            }
        }
    }
}

/// The legacy spellings of scalar operators (`containscs`, `notcontains`).
fn scalar_operators(root: &SyntaxNode, source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    for node in root
        .descendants()
        .filter(|n| matches!(n.kind(), K::COMPARISON_EXPR | K::IN_EXPR | K::BETWEEN_EXPR))
    {
        for token in node
            .children_with_tokens()
            .filter_map(NodeOrToken::into_token)
        {
            if matches!(token.kind(), K::WHITESPACE | K::COMMENT) {
                continue;
            }
            let text = token.text();
            if let Some(replacement) = catalog
                .scalar_operator(text)
                .and_then(|op| op.deprecated.as_ref())
            {
                out.push(
                    Diagnostic::warning(
                        codes::KQL_DEPRECATED_OPERATOR,
                        format!("'{text}' is a legacy spelling; use {replacement}"),
                        range_of(source, token.text_range()),
                    )
                    .with_suggestion(replacement.clone()),
                );
            }
        }
    }
}

/// Parameters of a function definition that take a table, `(T:(x:string))`
/// or `(T:(*))`: inside the body their names are tables.
fn tabular_parameters(definition: &SyntaxNode) -> Vec<String> {
    definition
        .children()
        .filter(|p| p.kind() == K::PARAMETER)
        .filter(|p| {
            p.children()
                .find(|c| c.kind() == K::TYPE)
                .and_then(|t| t.first_child())
                .is_some_and(|first| first.kind() == K::TABLE_TYPE)
        })
        .filter_map(|p| name_of(&p).map(|t| t.text().to_owned()))
        .collect()
}

/// Whether a `union` has `isfuzzy=true`.
fn is_fuzzy_union(node: &SyntaxNode) -> bool {
    node.children()
        .filter(|c| c.kind() == K::OPERATOR_OPTION)
        .any(|option| {
            let name = option
                .children_with_tokens()
                .filter_map(NodeOrToken::into_token)
                .find(|t| !matches!(t.kind(), K::WHITESPACE | K::COMMENT))
                .map(|t| t.text().to_ascii_lowercase());
            let value = option
                .children()
                .find(|c| c.kind() == K::OPTION_VALUE)
                .map(|v| v.text().to_string().to_ascii_lowercase());
            name.as_deref() == Some("isfuzzy") && value.as_deref() == Some("true")
        })
}

/// The tables a query reads: a source, a join or lookup side, a union leg.
/// Walks the tree with a stack of scopes: a function definition with tabular
/// parameters adds their names to its body's `let` names.
fn tables(
    root: &SyntaxNode,
    source: &str,
    catalog: &Catalog,
    lets: &BTreeSet<String>,
    out: &mut Vec<Diagnostic>,
) {
    if catalog.tables.is_empty() {
        return;
    }
    let mut scopes: Vec<BTreeSet<String>> = vec![lets.clone()];
    // Children go on the stack reversed, so they come off in document order.
    let mut stack: Vec<(SyntaxNode, usize)> = vec![(root.clone(), 0)];
    while let Some((node, scope)) = stack.pop() {
        let mut scope = scope;
        match node.kind() {
            K::FUNCTION_DEFINITION => {
                let params = tabular_parameters(&node);
                if !params.is_empty() {
                    let mut inner = scopes[scope].clone();
                    inner.extend(params);
                    scopes.push(inner);
                    scope = scopes.len() - 1;
                }
            }
            K::TABLE_REF => {
                let in_union = node.parent().is_some_and(|p| p.kind() == K::UNION_OPERATOR);
                let fuzzy = in_union && node.parent().is_some_and(|p| is_fuzzy_union(&p));
                if !fuzzy && let Some(name) = name_of(&node) {
                    check_table_named(
                        name.text(),
                        range_of(source, node.text_range()),
                        catalog,
                        &scopes[scope],
                        out,
                    );
                }
            }
            _ => {}
        }
        let children: Vec<SyntaxNode> = node.children().collect();
        stack.extend(children.into_iter().rev().map(|c| (c, scope)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Profile;

    fn parse_error(source: &str) -> Diagnostic {
        let catalog = Catalog::for_workspace(Profile::Sentinel, source);
        analyze(source, &catalog)
            .diagnostics
            .into_iter()
            .find(|d| d.code == codes::KQL_PARSE_ERROR)
            .expect("a syntax error")
    }

    #[test]
    fn the_syntax_error_says_what_was_expected_on_the_next_token() {
        let d = parse_error("T | take x");
        assert_eq!(d.message, "KQL syntax error: expected a number");
        assert_eq!((d.range.start.character, d.range.end.character), (9, 10));
        let d = parse_error("T | where a == 1 )");
        assert!(
            d.message
                .starts_with("KQL syntax error: unexpected input after the query; expected"),
            "{}",
            d.message
        );
    }

    /// At the end of the input the error is on the last token, even when the
    /// tree ends in an empty node (`last_token` would find none).
    #[test]
    fn at_the_end_the_syntax_error_is_on_the_last_token() {
        let d = parse_error("SigninLogs\n| project-rename User = ");
        assert_eq!(
            (
                d.range.start.line,
                d.range.start.character,
                d.range.end.character
            ),
            (1, 22, 23)
        );
    }
}
