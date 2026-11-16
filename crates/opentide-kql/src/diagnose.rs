//! The analysis on the new parser (#1230): every diagnostic of
//! `analyze_with_catalog` in its order (the syntax error, control commands,
//! unknown and `render` operators, functions, legacy scalar operators,
//! tables, the column pass, the performance checks), the HIR and the
//! highlight tokens, from one parse and one line index.

use crate::highlight::highlight_spans;
use crate::parser::parse_once;
use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use crate::syntax_util::{is_operator, legacy_kind, span, text};
use crate::{
    Catalog, Hir, HirOp, TYPED_LITERAL_TYPES, check_table_named, overlay_catalog_captures, perf,
    schema,
};
use opentide_core::{ByteSpan, Diagnostic, LineIndex, Range, codes, suggest};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_parse::SyntaxError;
use rowan::NodeOrToken;
use std::collections::BTreeSet;

/// An analysis on the new parser.
pub(crate) struct Analysis {
    /// The diagnostics, in the old order.
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) hir: Hir,
    pub(crate) tokens: Vec<HighlightToken>,
}

/// `analyze_with_catalog` on the new parser.
#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
pub(crate) fn analyze(source: &str, catalog: &Catalog) -> Analysis {
    let parsed = parse_once(source);
    let root = SyntaxNode::new_root(parsed.green);
    let lines = LineIndex::new(source);
    let mut diagnostics = Vec::new();
    if let Some(error) = parsed.errors.first() {
        diagnostics.push(syntax_error(&lines, &root, error));
    }
    let hir = lower(&root, source);
    control_commands(&root, &lines, &mut diagnostics);
    operators(&root, &lines, catalog, &mut diagnostics);
    let lets = let_names(&root);
    functions(&root, &lines, catalog, &lets, &mut diagnostics);
    scalar_operators(&root, &lines, catalog, &mut diagnostics);
    tables(&root, &lines, catalog, &lets, &mut diagnostics);
    let columns = schema::new_tree::analyze(&root, source, catalog, parsed.errors.is_empty());
    diagnostics.extend(columns.diagnostics.iter().cloned());
    perf::check(
        &pipelines(&root, parsed.errors.is_empty()),
        source,
        &columns,
        &mut diagnostics,
    );
    if let Some(error) = parsed.errors.first() {
        let boundary = lines.position(usize::from(quiet_from(&root, error)));
        quiet_after_the_error(&mut diagnostics, boundary);
    }
    let spec = HighlightSpec::load().expect("highlight spec");
    let mut spans = highlight_spans(&root);
    overlay_catalog_captures(source, &mut spans, catalog);
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    let tokens = tokens_from_spans(&spec, source, &refs).unwrap_or_default();
    Analysis {
        diagnostics,
        hir,
        tokens,
    }
}

/// Where findings stop on broken input: the start of the outermost operator,
/// `let` or source that holds the syntax error, or the error itself.
fn quiet_from(root: &SyntaxNode, error: &SyntaxError) -> rowan::TextSize {
    let at = error.gap.end();
    // The tokens on both sides of the error: the operator the error ends is
    // as much a fragment as the one it starts.
    let before = root.token_at_offset(error.gap.start()).left_biased();
    let after = root.token_at_offset(at).right_biased();
    [before, after]
        .into_iter()
        .flatten()
        .filter_map(|t| {
            t.parent()?
                .ancestors()
                .filter(|n| {
                    is_operator(n.kind())
                        || matches!(n.kind(), K::LET_STATEMENT | K::TABULAR_SOURCE)
                })
                .last()
        })
        .map(|n| crate::syntax_util::range(&n).start())
        .fold(at, rowan::TextSize::min)
}

/// Broken input must not get noisier: past the syntax error, and in the
/// operator that holds it, the parser's recovery has made nodes of fragments
/// (`| summ` is an unknown operator, a half-typed word a table), so only the
/// findings that end before `boundary` (and before the error) are kept with
/// the error (the first diagnostic).
fn quiet_after_the_error(diagnostics: &mut Vec<Diagnostic>, boundary: opentide_core::Position) {
    let key = |p: opentide_core::Position| (p.line, p.character);
    let Some(error) = diagnostics.first().map(|d| d.range.start) else {
        return;
    };
    let boundary = if key(error) < key(boundary) {
        error
    } else {
        boundary
    };
    let mut first = true;
    diagnostics.retain(|d| {
        let keep = first || key(d.range.end) <= key(boundary);
        first = false;
        keep
    });
}

/// The column pass alone (`opentide_kql::columns`), on the memoised parse.
pub(crate) fn columns(source: &str, catalog: &Catalog) -> schema::Analysis {
    let parsed = parse_once(source);
    let root = SyntaxNode::new_root(parsed.green);
    schema::new_tree::analyze(&root, source, catalog, parsed.errors.is_empty())
}

/// The tabular expressions of the query, in source order, as the
/// performance checks read them; none in a query that does not parse
/// (`clean`), whose operators recovery may have made of fragments: broken
/// input gets no performance hint (the text-based scope checks still run).
fn pipelines(root: &SyntaxNode, clean: bool) -> Vec<perf::Pipeline> {
    root.descendants()
        .filter(|n| clean && n.kind() == K::TABULAR_EXPRESSION)
        .map(|expr| perf::Pipeline {
            span: span(&expr),
            ops: expr
                .children()
                .filter(|op| is_operator(op.kind()))
                .map(|op| perf::Op {
                    kind: legacy_kind(op.kind()),
                    span: span(&op),
                })
                .collect(),
        })
        .collect()
}

/// The HIR (`opentide_kql::lower`): the `let`s, the first source, and every
/// operator with its text, in source order; a control command alone.
pub(crate) fn lower(root: &SyntaxNode, source: &str) -> Hir {
    let mut lets = Vec::new();
    let mut source_name = String::new();
    let mut operators = Vec::new();
    for node in root.descendants() {
        match node.kind() {
            K::LET_STATEMENT => {
                let name = name_of(&node)
                    .map(|t| t.text().to_owned())
                    .unwrap_or_default();
                let value = node
                    .first_child()
                    .map(|v| text(source, &v).to_owned())
                    .unwrap_or_default();
                lets.push((name, value));
            }
            K::CONTROL_COMMAND => {
                let name = name_of(&node)
                    .map(|t| t.text().to_owned())
                    .unwrap_or_default();
                return Hir::ControlCommand { name };
            }
            K::TABULAR_SOURCE if source_name.is_empty() => {
                text(source, &node).trim().clone_into(&mut source_name);
            }
            kind if is_operator(kind) => {
                let name = if kind == K::KEYWORD_OPERATOR {
                    crate::syntax_util::tokens(&node)
                        .next()
                        .map_or_else(|| "unknown".to_owned(), |t| t.text().to_owned())
                } else {
                    legacy_kind(kind)
                        .trim_end_matches("_operator")
                        .replace('_', "-")
                };
                operators.push(HirOp {
                    name,
                    args: text(source, &node).to_owned(),
                });
            }
            _ => {}
        }
    }
    if source_name.is_empty() && operators.is_empty() && lets.is_empty() {
        Hir::Empty
    } else {
        Hir::Query {
            lets,
            source: source_name,
            operators,
        }
    }
}

/// The range of a node or token, at least one byte wide.
fn range_of(lines: &LineIndex, range: rowan::TextRange) -> Range {
    let start = usize::from(range.start());
    lines.range(ByteSpan::new(
        start,
        usize::from(range.end()).max(start + 1),
    ))
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
fn syntax_error(lines: &LineIndex, root: &SyntaxNode, error: &SyntaxError) -> Diagnostic {
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
    Diagnostic::error(codes::KQL_PARSE_ERROR, message, range_of(lines, range))
}

/// `.show tables`: reported once.
fn control_commands(root: &SyntaxNode, lines: &LineIndex, out: &mut Vec<Diagnostic>) {
    if let Some(node) = root.descendants().find(|n| n.kind() == K::CONTROL_COMMAND) {
        let name = name_of(&node).map_or_else(|| ".".into(), |t| t.text().to_owned());
        out.push(Diagnostic::error(
            codes::KQL_CONTROL_COMMAND_UNSUPPORTED,
            format!("KQL control command '.{name}' is not valid in detections"),
            range_of(lines, node.text_range()),
        ));
    }
}

/// Unknown operators, and `render`.
fn operators(root: &SyntaxNode, lines: &LineIndex, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
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
                        range_of(lines, node.text_range()),
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
                range_of(lines, node.text_range()),
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
    lines: &LineIndex,
    catalog: &Catalog,
    lets: &BTreeSet<String>,
    out: &mut Vec<Diagnostic>,
) {
    for node in root.descendants().filter(|n| n.kind() == K::FUNCTION_CALL) {
        let Some(name_token) = name_of(&node) else {
            continue;
        };
        let name = name_token.text().to_owned();
        let name_range = range_of(lines, name_token.text_range());
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
                range_of(lines, node.text_range()),
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
fn scalar_operators(
    root: &SyntaxNode,
    lines: &LineIndex,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
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
                        range_of(lines, token.text_range()),
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
    lines: &LineIndex,
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
                        range_of(lines, node.text_range()),
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
