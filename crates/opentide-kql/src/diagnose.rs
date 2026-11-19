//! The analysis on the new parser (#1230): every diagnostic of
//! `analyze_with_catalog` in its order (the syntax error, control commands,
//! unknown and `render` operators, functions, legacy scalar operators,
//! tables, the column pass, the performance checks), the HIR and the
//! highlight tokens, from one parse and one line index.

use crate::highlight::highlight_span;
use crate::parser::parse_once;
use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use crate::syntax_util::{is_operator, legacy_kind, span, text, token_at};
use crate::{
    Catalog, CatalogRef, Hir, HirOp, TYPED_LITERAL_TYPES, check_table_named,
    overlay_catalog_captures, perf, schema,
};
use opentide_core::{ByteSpan, Diagnostic, LineIndex, Range, codes, suggest};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_in};
use opentide_parse::SyntaxError;
use rowan::NodeOrToken;
use std::collections::BTreeSet;
use std::rc::Rc;

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
    // One walk of the tree (ADR 0014 §5a): the HIR, the node checks below,
    // the syntax error's position and the highlight read it, in preorder,
    // where each walked the tree again and rowan allocated a cursor for every
    // node of every walk. The tokens, most of the elements, are read as the
    // walk meets them and not kept, so their cursors are freed as they were;
    // only the nodes are kept, until the passes that read them are done. The
    // column pass (which follows each pipeline's structure with its scope,
    // not the tree's order) and the error path's lookups still step through
    // the tree themselves.
    let mut nodes: Vec<SyntaxNode> = Vec::new();
    let mut spans = Vec::new();
    let at = parsed.errors.first().map(|error| error.gap.end());
    let mut error_tokens = ErrorTokens::default();
    // Each node's depth, beside it: the tables' scopes are rebuilt from it.
    let mut depths: Vec<usize> = Vec::new();
    opentide_parse::walk_once(&root, |element, depth| {
        #[cfg(test)]
        tests::VISITS.set(tests::VISITS.get() + 1);
        highlight_span(&element, &mut spans);
        match element {
            NodeOrToken::Node(node) => {
                nodes.push(node);
                depths.push(depth);
            }
            NodeOrToken::Token(token) => {
                if let Some(at) = at {
                    error_tokens.see(&token, at);
                }
            }
        }
    });
    let mut diagnostics = Vec::new();
    if let Some(error) = parsed.errors.first() {
        diagnostics.push(syntax_error(&lines, &error_tokens, error));
    }
    let hir = lower_nodes(&nodes, source);
    control_commands(&nodes, &lines, &mut diagnostics);
    operators(&nodes, &lines, catalog, &mut diagnostics);
    let lets = let_names(&nodes);
    functions(&nodes, &lines, catalog, &lets, &mut diagnostics);
    scalar_operators(&nodes, &lines, catalog, &mut diagnostics);
    let _ = tables(&nodes, &depths, &lines, catalog, &lets, &mut diagnostics);
    // What the later passes need of the nodes, taken now, so that the nodes
    // are freed before the column pass.
    let pipes = pipelines(&nodes, parsed.errors.is_empty());
    let whole = if parsed.errors.is_empty() {
        Vec::new()
    } else {
        whole_unknown_operators(&nodes, &lines)
    };
    drop(nodes);
    drop(depths);
    let columns =
        schema::new_tree::analyze(&root, source, &lines, catalog, parsed.errors.is_empty());
    diagnostics.extend(columns.diagnostics.iter().cloned());
    perf::check(&pipes, &lines, &columns, &mut diagnostics);
    if let Some(error) = parsed.errors.first() {
        with_typed_literal_hint(&mut diagnostics);
        let boundary = lines.position(usize::from(quiet_from(&root, error)));
        quiet_after_the_error(&mut diagnostics, boundary, &whole);
    }
    // The scope checks scan tokens, not the tree: the old engine gave them on
    // broken input too, and `union *` and `search *`, which both engines
    // reject, are the shapes they exist for.
    perf::check_scope(source, &lines, &mut diagnostics);
    let spec = HighlightSpec::shared().expect("highlight spec");
    overlay_catalog_captures(source, &mut spans, catalog);
    let tokens = tokens_in(spec, &lines, &spans).unwrap_or_default();
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
    let before = token_at(root, error.gap.start(), true);
    let after = token_at(root, at, false);
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

/// The ranges of the unknown operators that parsed whole: no error node in
/// them and every bracket closed (`summarzie count()`, not `summarzie
/// count(`). The syntax error that follows one is what its mistyped name
/// caused, so its "did you mean" stays ([`quiet_after_the_error`]).
fn whole_unknown_operators(nodes: &[SyntaxNode], lines: &LineIndex) -> Vec<Range> {
    nodes
        .iter()
        .filter(|n| n.kind() == K::UNKNOWN_OPERATOR)
        .filter(|n| {
            let mut depth = 0_i64;
            let mut broken = false;
            for element in n.descendants_with_tokens() {
                match element.kind() {
                    K::ERROR => broken = true,
                    K::L_PAREN | K::L_BRACKET | K::L_BRACE => depth += 1,
                    K::R_PAREN | K::R_BRACKET | K::R_BRACE => depth -= 1,
                    _ => {}
                }
            }
            !broken && depth == 0
        })
        .map(|n| range_of(lines, n.text_range()))
        .collect()
}

/// Broken input must not get noisier: past the syntax error, and in the
/// operator that holds it, the parser's recovery has made nodes of fragments
/// (`| summ` is an unknown operator, a half-typed word a table), so only the
/// findings that end before `boundary` (and before the error) are kept with
/// the error (the first diagnostic), and the unknown operators in `whole`
/// that end before the error.
fn quiet_after_the_error(
    diagnostics: &mut Vec<Diagnostic>,
    boundary: opentide_core::Position,
    whole: &[Range],
) {
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
        // A mistyped operator name (`| summarzie count() by a`) is why the
        // query does not parse: its "did you mean" stays, as on the old
        // engine, when the operator parsed whole before the error.
        let explains = d.code == codes::KQL_UNKNOWN_OPERATOR
            && key(d.range.end) <= key(error)
            && whole.contains(&d.range);
        let keep = first || explains || key(d.range.end) <= key(boundary);
        first = false;
        keep
    });
}

/// When a `datetime(` the typed-literal check explains (its value and `)`
/// not on one line) comes before the syntax error, the explanation joins the
/// error's message, once: it says more than the error, and the quieting would
/// drop it as a second finding in the broken operator (the old engine gave it
/// where its tree held the call, which this tree does more often).
fn with_typed_literal_hint(diagnostics: &mut Vec<Diagnostic>) {
    let key = |p: opentide_core::Position| (p.line, p.character);
    let Some(at) = diagnostics.first().map(|e| key(e.range.start)) else {
        return;
    };
    // The last hint that starts before the error: the unclosed `datetime(`
    // the error is in or comes after (`datetime(2024-01-01` and `)` on the
    // next line).
    let Some(index) = diagnostics
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, d)| d.code == codes::KQL_PARSE_ERROR && key(d.range.start) <= at)
        .max_by_key(|(_, d)| key(d.range.start))
        .map(|(i, _)| i)
    else {
        return;
    };
    let hint = diagnostics.remove(index);
    diagnostics[0].message = format!("{}; {}", diagnostics[0].message, hint.message);
}

thread_local! {
    /// The column passes this thread ran: what the memo's test counts.
    static COLUMN_PASSES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// The last text [`columns`] ran on, the catalog it ran against, and the
    /// pass.
    static LAST_COLUMNS: std::cell::RefCell<Option<(String, CatalogRef, Rc<schema::Analysis>)>> =
        const { std::cell::RefCell::new(None) };
}

/// How many column passes this thread has run (not counting memo hits).
#[cfg(test)]
pub(crate) fn column_passes() -> u64 {
    COLUMN_PASSES.with(std::cell::Cell::get)
}

/// The column pass alone (`opentide_kql::columns`, a column's hover), on the
/// memoised parse, and itself memoised for the last text and catalog: hover
/// asks for it at each offset of the same text, and on a query of 30 nested
/// `join`s 25 hovers took 10 s in a debug build, one pass each (#1424). The
/// memo holds the catalog it ran against (a profile's bundled one, or a
/// workspace's with declared columns, which `Catalog::for_workspace` keeps
/// while the declarations stay the same) and compares it by identity: held,
/// its address cannot be reused by another catalog.
pub(crate) fn columns(source: &str, catalog: &CatalogRef) -> Rc<schema::Analysis> {
    if let Some(hit) = LAST_COLUMNS.with(|last| {
        last.borrow()
            .as_ref()
            .filter(|(text, held, _)| text == source && same_catalog(held, catalog))
            .map(|(_, _, analysis)| Rc::clone(analysis))
    }) {
        return hit;
    }
    let parsed = parse_once(source);
    let root = SyntaxNode::new_root(parsed.green);
    COLUMN_PASSES.with(|n| n.set(n.get() + 1));
    let analysis = Rc::new(schema::new_tree::analyze(
        &root,
        source,
        &LineIndex::new(source),
        catalog,
        parsed.errors.is_empty(),
    ));
    LAST_COLUMNS.with(|last| {
        *last.borrow_mut() = Some((source.to_owned(), catalog.clone(), Rc::clone(&analysis)));
    });
    analysis
}

/// The same catalog: the same static, or the same `Arc`.
fn same_catalog(a: &CatalogRef, b: &CatalogRef) -> bool {
    match (a, b) {
        (CatalogRef::Bundled(a), CatalogRef::Bundled(b)) => std::ptr::eq(*a, *b),
        (CatalogRef::Declared(a), CatalogRef::Declared(b)) => std::sync::Arc::ptr_eq(a, b),
        _ => false,
    }
}

/// The tabular expressions of the query, in source order, as the
/// performance checks read them; none in a query that does not parse
/// (`clean`), whose operators recovery may have made of fragments: broken
/// input gets no performance hint (the text-based scope checks still run).
fn pipelines(nodes: &[SyntaxNode], clean: bool) -> Vec<perf::Pipeline> {
    nodes
        .iter()
        .filter(|n| clean && n.kind() == K::TABULAR_EXPRESSION)
        .map(|expr| perf::Pipeline {
            span: span(expr),
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
    // Walked lazily: a control command ends the walk at its node.
    lower_nodes(root.descendants(), source)
}

/// [`lower`] of a tree's nodes in preorder.
fn lower_nodes<N: std::borrow::Borrow<SyntaxNode>>(
    nodes: impl IntoIterator<Item = N>,
    source: &str,
) -> Hir {
    let mut lets = Vec::new();
    let mut source_name = String::new();
    let mut operators = Vec::new();
    for node in nodes {
        let node = node.borrow();
        match node.kind() {
            K::LET_STATEMENT => {
                let name = name_of(node)
                    .map(|t| t.text().to_owned())
                    .unwrap_or_default();
                let value = node
                    .first_child()
                    .map(|v| text(source, &v).to_owned())
                    .unwrap_or_default();
                lets.push((name, value));
            }
            K::CONTROL_COMMAND => {
                let name = name_of(node)
                    .map(|t| t.text().to_owned())
                    .unwrap_or_default();
                return Hir::ControlCommand { name };
            }
            K::TABULAR_SOURCE if source_name.is_empty() => {
                text(source, node).trim().clone_into(&mut source_name);
            }
            kind if is_operator(kind) => {
                let name = if kind == K::KEYWORD_OPERATOR {
                    crate::syntax_util::tokens(node)
                        .next()
                        .map_or_else(|| "unknown".to_owned(), |t| t.text().to_owned())
                } else {
                    legacy_kind(kind)
                        .trim_end_matches("_operator")
                        .replace('_', "-")
                };
                operators.push(HirOp {
                    name,
                    args: text(source, node).to_owned(),
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

/// The tokens a syntax error is placed on, met in document order: the first
/// significant one from the error's end on, and the last significant one.
#[derive(Default)]
struct ErrorTokens {
    next: Option<rowan::TextRange>,
    last: Option<rowan::TextRange>,
}

impl ErrorTokens {
    fn see(&mut self, token: &SyntaxToken, at: rowan::TextSize) {
        if matches!(token.kind(), K::WHITESPACE | K::COMMENT) {
            return;
        }
        let range = token.text_range();
        if self.next.is_none() && range.start() >= at {
            self.next = Some(range);
        }
        self.last = Some(range);
    }
}

/// The one syntax error the old engine reported, with what the parser
/// expected: at the token the error stands before.
fn syntax_error(lines: &LineIndex, tokens: &ErrorTokens, error: &SyntaxError) -> Diagnostic {
    let mut message = format!("KQL syntax error: {}", error.message);
    if !error.message.starts_with("expected")
        && let Some(expected) = expected_phrase(error)
    {
        message.push_str(&format!("; expected {expected}"));
    }
    let at = error.gap.end();
    // The first significant token from `at` on, from the walk: rowan's
    // `token_at_offset` and `next_token` recurse once per tree level. Past the
    // last token, the error is on that token (not `last_token`, which stops
    // at an empty last node): an empty range at the end of the text, often a
    // blank line, is not visible in an editor.
    let range = tokens
        .next
        .or(tokens.last)
        .unwrap_or_else(|| rowan::TextRange::empty(at));
    Diagnostic::error(codes::KQL_PARSE_ERROR, message, range_of(lines, range))
}

/// `.show tables`: reported once.
fn control_commands(nodes: &[SyntaxNode], lines: &LineIndex, out: &mut Vec<Diagnostic>) {
    if let Some(node) = nodes.iter().find(|n| n.kind() == K::CONTROL_COMMAND) {
        let name = name_of(node).map_or_else(|| ".".into(), |t| t.text().to_owned());
        out.push(Diagnostic::error(
            codes::KQL_CONTROL_COMMAND_UNSUPPORTED,
            format!("KQL control command '.{name}' is not valid in detections"),
            range_of(lines, node.text_range()),
        ));
    }
}

/// Unknown operators, and `render`.
fn operators(
    nodes: &[SyntaxNode],
    lines: &LineIndex,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    for node in nodes {
        match node.kind() {
            K::UNKNOWN_OPERATOR => {
                let name = name_of(node)
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

/// Names bound by `let` or `declare query_parameters` anywhere in the query.
fn let_names(nodes: &[SyntaxNode]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut add = |node: &SyntaxNode| {
        if let Some(name) = name_of(node) {
            names.insert(name.text().to_owned());
        }
    };
    // One walk over the nodes: a second one, for the parameters alone, cost
    // every query (#1646).
    for node in nodes {
        match node.kind() {
            K::LET_STATEMENT => add(node),
            K::QUERY_PARAMETERS_STATEMENT => node
                .children()
                .filter(|c| c.kind() == K::PARAMETER)
                .for_each(|c| add(&c)),
            _ => {}
        }
    }
    names
}

/// Calls: typed literals written as calls, plugins, deprecated and
/// misspelled functions.
fn functions(
    nodes: &[SyntaxNode],
    lines: &LineIndex,
    catalog: &Catalog,
    lets: &BTreeSet<String>,
    out: &mut Vec<Diagnostic>,
) {
    for node in nodes.iter().filter(|n| n.kind() == K::FUNCTION_CALL) {
        let Some(name_token) = name_of(node) else {
            continue;
        };
        let name = name_token.text().to_owned();
        let name_range = range_of(lines, name_token.text_range());
        let parent = node.parent().map(|p| p.kind());
        let is_plugin = parent == Some(K::EVALUATE_OPERATOR);
        let function = catalog.function(&name);
        if parent == Some(K::QUALIFIED_TABLE) {
            // A scope of a table in another database (`cluster("c")`,
            // `database("d")`, `workspace("w")`, `app("a")`), not a function.
        } else if lets.contains(&name) {
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
            // Only a likely typo of a known function: within two edits. The
            // distance is at least the difference in length, and at least the
            // characters one has that the other lacks: a name too far by
            // either is not measured.
            let length = name.chars().count();
            if let Some(suggestion) = suggest::best(
                &name,
                catalog
                    .functions
                    .iter()
                    .filter(|f| f.deprecated.is_none())
                    .map(|f| f.name.as_str())
                    .filter(|f| f.chars().count().abs_diff(length) <= 2)
                    .filter(|f| suggest::bag_distance(f, &name).is_none_or(|d| d <= 2))
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
    nodes: &[SyntaxNode],
    lines: &LineIndex,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    for node in nodes
        .iter()
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
/// Reads the walk's nodes, in preorder with their depths, with a stack of
/// scopes: a function definition with tabular parameters adds their names to
/// its body's `let` names, as a layer over the scope it is in, for the nodes
/// below it (deeper, until the depth comes back to its own). Each layer holds
/// its own parameters only: copying the scope's names for each function made
/// `n` functions with tabular parameters quadratic (#1424). Returns how many
/// names the layers hold, the work count a test bounds.
fn tables(
    nodes: &[SyntaxNode],
    depths: &[usize],
    lines: &LineIndex,
    catalog: &Catalog,
    lets: &BTreeSet<String>,
    out: &mut Vec<Diagnostic>,
) -> usize {
    if catalog.tables.is_empty() {
        return 0;
    }
    // (the layer it is over, its parameters). Layer 0 holds no names: the
    // walk ends there, at the query's `lets`.
    let mut scopes: Vec<(usize, BTreeSet<String>)> = vec![(0, BTreeSet::new())];
    let binds = |scopes: &[(usize, BTreeSet<String>)], mut at: usize, name: &str| loop {
        if scopes[at].1.contains(name) {
            return true;
        }
        if at == 0 {
            return lets.contains(name);
        }
        at = scopes[at].0;
    };
    // The open function scopes, (the depth of their definition, the layer),
    // and the node at each depth of the path to the current one.
    let mut open: Vec<(usize, usize)> = Vec::new();
    let mut path: Vec<usize> = Vec::new();
    for (index, (node, &depth)) in nodes.iter().zip(depths).enumerate() {
        while open.last().is_some_and(|&(at, _)| at >= depth) {
            open.pop();
        }
        // Preorder: a node is at most one level below the one before it.
        debug_assert!(depth <= path.len(), "a node deeper than its parent");
        path.truncate(depth);
        path.push(index);
        let scope = open.last().map_or(0, |&(_, layer)| layer);
        match node.kind() {
            K::FUNCTION_DEFINITION => {
                let params = tabular_parameters(node);
                if !params.is_empty() {
                    scopes.push((scope, params.into_iter().collect()));
                    open.push((depth, scopes.len() - 1));
                }
            }
            K::TABLE_REF => {
                let parent = depth
                    .checked_sub(1)
                    .and_then(|d| path.get(d))
                    .map(|&i| &nodes[i]);
                let fuzzy =
                    parent.is_some_and(|p| p.kind() == K::UNION_OPERATOR && is_fuzzy_union(p));
                // Another database's table (`database("d").T`) is not this
                // workspace's to check.
                let elsewhere = parent.is_some_and(|p| p.kind() == K::QUALIFIED_TABLE);
                if !fuzzy
                    && !elsewhere
                    && let Some(name) = crate::syntax_util::table_token(node)
                {
                    check_table_named(
                        crate::schema::unquote_name(name.text()),
                        range_of(lines, node.text_range()),
                        catalog,
                        |name| binds(&scopes, scope, name),
                        out,
                    );
                }
            }
            _ => {}
        }
    }
    scopes.iter().map(|(_, names)| names.len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Profile;

    /// A tree's nodes in preorder and their depths, as `analyze`'s walk
    /// gives them.
    fn nodes_and_depths(root: &SyntaxNode) -> (Vec<SyntaxNode>, Vec<usize>) {
        let (mut nodes, mut depths) = (Vec::new(), Vec::new());
        opentide_parse::walk_once(root, |element, depth| {
            if let NodeOrToken::Node(node) = element {
                nodes.push(node);
                depths.push(depth);
            }
        });
        (nodes, depths)
    }

    thread_local! {
        /// The elements `analyze`'s walk visited on this thread.
        pub(super) static VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// One walk serves the HIR, the node checks, the syntax error and the
    /// highlight (ADR 0014 §5a): `analyze`'s walk visits each element of the
    /// tree once, on broken input too. What it holds is that one walk, not
    /// the others: the column pass and the error path's lookups still step
    /// through the tree themselves and are not counted here; the node checks
    /// and the tables' scopes are held to the one walk by taking its nodes as
    /// a slice.
    #[test]
    fn an_analysis_visits_each_element_once() {
        for source in [
            "let n = 5;\nSecurityEvent\n| where EventID == 4624 and Account !has \"svc\"\n\
             | summarize count() by Account, bin(TimeGenerated, 1h)\n| top n by count_",
            "SigninLogs | where UserPrincipalName =~ \"a\" | summ",
            ".show tables",
        ] {
            let catalog = Catalog::for_workspace(Profile::Sentinel, source);
            let elements = SyntaxNode::new_root(parse_once(source).green)
                .descendants_with_tokens()
                .count();
            let before = VISITS.get();
            let _ = analyze(source, &catalog);
            assert_eq!(VISITS.get() - before, elements, "{source:?}");
        }
    }

    /// `lower` stops at a control command, as it did before the walk merge:
    /// its lazy walk yields the nodes up to the command's, not the tree's.
    #[test]
    fn lower_stops_at_a_control_command() {
        let source = ".show tables | where x == 1 and y == 2 | project a, b, c";
        let root = SyntaxNode::new_root(parse_once(source).green);
        let all = root.descendants().count();
        let mut yielded = 0;
        let hir = lower_nodes(root.descendants().inspect(|_| yielded += 1), source);
        assert!(matches!(hir, Hir::ControlCommand { .. }), "{hir:?}");
        assert!(yielded < all, "{yielded} of {all} nodes");
        assert_eq!(format!("{:?}", lower(&root, source)), format!("{hir:?}"));
    }

    /// The scopes of `tables` hold each tabular parameter once, however many
    /// `let` names are in scope (#1424): copying them per function was
    /// quadratic, 4.7 s for 4,000 functions in a debug build.
    #[test]
    fn table_scopes_hold_each_parameter_once() {
        let n = 300;
        let mut source = String::new();
        for i in 0..n {
            source.push_str(&format!(
                "let f{i} = (x:long, T:(*)) {{ SigninLogs | extend c = x }};\n"
            ));
        }
        source.push_str("let g = (T:(*), U:(*)) { T | union U };\nNopeTable | take 1");
        let catalog = Catalog::for_workspace(Profile::Sentinel, &source);
        let parsed = parse_once(&source);
        let root = SyntaxNode::new_root(parsed.green.clone());
        let (nodes, depths) = nodes_and_depths(&root);
        let lets = let_names(&nodes);
        let mut out = Vec::new();
        let held = tables(
            &nodes,
            &depths,
            &LineIndex::new(&source),
            &catalog,
            &lets,
            &mut out,
        );
        assert_eq!(held, n + 2);
        // A parameter is not a table; an unknown name still is reported.
        assert!(out.iter().all(|d| !d.message.contains("'T'")), "{out:?}");
        assert!(
            out.iter().any(|d| d.message.contains("NopeTable")),
            "{out:?}"
        );
    }

    /// The tables `analyze` reports unknown in `source` (Sentinel).
    /// A tabular parameter names a table inside its function only: the
    /// scope a definition opens ends with its body, for its siblings and for
    /// what follows, and a nested definition's scope is over its parent's.
    #[test]
    fn a_parameter_scope_ends_with_its_function() {
        assert_eq!(
            unknown_tables("let f = (T:(*)) { T };\nlet g = (U:(*)) { T | union U };\nT | union U"),
            ["T", "T", "U"]
        );
        assert_eq!(
            unknown_tables(
                "let f = (T:(*)) { let g = (U:(*)) { T | union U }; g(T) | union U };\nT"
            ),
            ["U", "T"]
        );
    }

    fn unknown_tables(source: &str) -> Vec<String> {
        let catalog = Catalog::for_workspace(Profile::Sentinel, source);
        analyze(source, &catalog)
            .diagnostics
            .into_iter()
            .filter(|d| d.code == codes::KQL_UNKNOWN_TABLE)
            .filter_map(|d| d.message.split('\'').nth(1).map(str::to_string))
            .collect()
    }

    /// A tabular parameter is bound in its function's body and in every
    /// function nested in it, through each layer out to the query's `let`
    /// names, and nowhere after its function ends (#1424's layers).
    #[test]
    fn tabular_parameters_bind_through_the_layers() {
        assert_eq!(
            unknown_tables(
                "let f = (T:(*)) { let g = (U:(*)) { T | union U }; g(T) };\nf(SigninLogs)"
            ),
            Vec::<String>::new()
        );
        assert_eq!(
            unknown_tables("let f = (T:(*)) { T };\nT | take 1"),
            vec!["T".to_string()]
        );
        assert_eq!(
            unknown_tables(
                "let L = SigninLogs;\n\
                 let f = (A:(*)) { let g = (B:(*)) { let h = (C:(*)) { A | union B, C, D, L }; h(B) }; g(A) };\n\
                 f(SigninLogs)"
            ),
            vec!["D".to_string()]
        );
    }

    /// Hover at many offsets of one text runs the column pass once (#1424),
    /// and a different text or profile runs it again.
    #[test]
    fn hover_runs_the_column_pass_once_per_text() {
        let mut q = String::from("SecurityEvent");
        for _ in 0..10 {
            q = format!("SecurityEvent | join ({q}) on Account");
        }
        let before = column_passes();
        for offset in (0..q.len()).step_by(7) {
            let _ = crate::hover(&q, offset, Profile::Sentinel);
        }
        assert_eq!(column_passes() - before, 1);
        let _ = crate::columns(&q, Profile::Sentinel);
        assert_eq!(column_passes() - before, 1);
        let _ = crate::columns(&q, Profile::Defender);
        let _ = crate::columns("SigninLogs | project AppId", Profile::Sentinel);
        assert_eq!(column_passes() - before, 3);
    }

    /// With a workspace that declares columns, hover still runs the column
    /// pass once per text: the memo holds the declared catalog `Arc` that
    /// `Catalog::for_workspace` keeps while the declarations stay the same.
    #[test]
    fn hover_memoises_against_a_declared_catalog() {
        let declared = opentide_core::datasets::DeclaredDatasets::from_visibility(
            "[[logsources]]\nname = \"Contoso_Audit_CL\"\ndescription = \"x\"\n\
             system = \"sentinel\"\n\n[logsources.columns]\nActor_s = { type = \"string\" }\n",
        )
        .expect("visibility.toml");
        let _scope = opentide_core::datasets::scope_thread(Some(declared));
        let q = "Contoso_Audit_CL | where Actor_s == 'a' | join (SecurityEvent) on Account";
        assert!(matches!(
            Catalog::for_workspace(Profile::Sentinel, q),
            CatalogRef::Declared(_)
        ));
        let before = column_passes();
        for offset in 0..q.len() {
            let _ = crate::hover(q, offset, Profile::Sentinel);
        }
        assert_eq!(column_passes() - before, 1);
    }

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

    /// Broken input is not noisier, and the `datetime(` hint is not lost: it
    /// joins the syntax error it explains (#1230).
    #[test]
    fn the_typed_literal_hint_joins_the_syntax_error() {
        for source in ["print x = datetime(2024-01-01", "print a = datetime(2024-"] {
            let catalog = Catalog::for_workspace(Profile::Sentinel, source);
            let diagnostics = analyze(source, &catalog).diagnostics;
            assert_eq!(diagnostics.len(), 1, "{source}: {diagnostics:?}");
            assert!(
                diagnostics[0]
                    .message
                    .contains("'datetime(' starts a typed literal"),
                "{source}: {diagnostics:?}"
            );
        }
    }

    /// The scope checks read tokens, not the tree: they stay on broken input,
    /// as on the old engine (`union *` is the shape they exist for; it parses,
    /// and the trailing pipe breaks the query).
    #[test]
    fn the_scope_checks_run_on_broken_input() {
        let source = "search \"a\" | union * |";
        let catalog = Catalog::for_workspace(Profile::Sentinel, source);
        let codes: Vec<String> = analyze(source, &catalog)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect();
        assert_eq!(
            codes,
            [
                codes::KQL_PARSE_ERROR,
                codes::KQL_UNSCOPED_SEARCH,
                codes::KQL_UNSCOPED_UNION
            ]
        );
    }

    /// A wildcard table (`Sign*`, `*Logs`, `*`) in a union or a search's `in`
    /// list is a pattern, as Kusto takes it: no syntax error, no table named
    /// by its first word (`'Sign' is not a table`), and only a bare `*` reads
    /// every table.
    #[test]
    fn wildcard_tables_are_patterns() {
        let cases: [(&str, &[&str]); 9] = [
            (
                "union isfuzzy=false Nope1, Sign*",
                &[codes::KQL_UNKNOWN_TABLE],
            ),
            ("union Sign*", &[]),
            ("union Signin*Logs, *Events", &[]),
            (
                "union withsource=T Sign*, Nope1",
                &[codes::KQL_UNKNOWN_TABLE],
            ),
            ("SigninLogs | union kind=outer Sec*", &[]),
            ("union *", &[codes::KQL_UNSCOPED_UNION]),
            ("union withsource=T *", &[codes::KQL_UNSCOPED_UNION]),
            ("search in (Sec*, SigninLogs) \"x\"", &[]),
            (
                "search in (SecurityEvent, *) \"x\"",
                &[codes::KQL_WILDCARD_TABLE],
            ),
        ];
        for (source, expected) in cases {
            assert_eq!(codes_of(source), expected, "{source}");
        }
        assert_eq!(
            unknown_tables("union isfuzzy=false Nope1, Sign*"),
            ["Nope1"]
        );
    }

    /// A table in another scope (`database("d").T`, `cluster("c").database("d").T`,
    /// `workspace("w").T`, `app("a").T`) or by quoted name (`['T']`) parses, in
    /// a query's source, a union leg and a join's side, as Kusto takes it.
    /// Another database's table is not this workspace's to check; a quoted
    /// name is checked as its name.
    #[test]
    fn qualified_and_quoted_tables_parse() {
        for source in [
            "database(\"d\").T | take 1",
            "cluster(\"c\").database(\"d\").T | take 1",
            "workspace(\"w\").SecurityEvent | take 1",
            "app(\"a\").requests | take 1",
            "union database(\"db\").T1, cluster(\"c\").database(\"db\").T2",
            "union workspace(\"w\").Sec*, SigninLogs",
            "cluster(\"c\").database(\"d\").['My Table'] | take 1",
            "SecurityEvent | join (database(\"d\").T) on Key",
            "['SecurityEvent'] | take 1",
            "search in (['SecurityEvent'], Sec*) \"x\"",
        ] {
            assert!(
                codes_of(source).is_empty(),
                "{source}: {:?}",
                codes_of(source)
            );
        }
        assert_eq!(unknown_tables("['NopeTable'] | take 1"), ["NopeTable"]);
        assert_eq!(
            unknown_tables("union ['SecurityEvent'], ['Nope2']"),
            ["Nope2"]
        );
        // Not tables Kusto takes: a scope with no table, scopes out of order
        // or in another case, a pattern outside a union, a quoted name that
        // is not a plain string in touching brackets.
        for broken in [
            "cluster(\"c\").database(\"d\")",
            "cluster(\"c\").database(\"d\") | take 1",
            "cluster(\"c\").T",
            "cluster(\"c\").cluster(\"d\").T",
            "workspace(\"w\").database(\"d\").T",
            "DATABASE(\"d\").T",
            "database(\"d\").Sec* | take 1",
            "database(\"d\").[ 'T' ]",
            "database(\"d\").[@'T']",
        ] {
            assert_eq!(codes_of(broken), [codes::KQL_PARSE_ERROR], "{broken}");
        }
        // A scope call with no dot after it is still a call.
        assert!(codes_of("print database(\"d\")").is_empty());
    }

    /// `where * has "x"`: a star on the left of a string operator or `==`
    /// searches every column, as Kusto takes it; on the left of anything else
    /// (`!=`, `<`, `in`, `has_any`) it is still an error, as in Kusto.
    /// `2 * 3`, `count(*)` and a bare `where *` are as before.
    #[test]
    fn a_star_searches_every_column() {
        for source in [
            "SecurityEvent | where * has \"x\"",
            "SecurityEvent | where * contains \"x\"",
            "SecurityEvent | where * !has \"x\"",
            "SecurityEvent | where * =~ \"x\"",
            "SecurityEvent | where * matches regex \"x\"",
            "SecurityEvent | where * == \"x\"",
            "SecurityEvent | where * : \"x\"",
            "search in (SecurityEvent) * : \"x\"",
            "SecurityEvent | where * startswith \"x\" and EventID == 1",
            "SecurityEvent | extend y = 2 * 3",
            "SecurityEvent | summarize count(*)",
        ] {
            assert!(
                codes_of(source).is_empty(),
                "{source}: {:?}",
                codes_of(source)
            );
        }
        for not_kusto in [
            "SecurityEvent | where *",
            "SecurityEvent | where * != \"x\"",
            "SecurityEvent | where * < 5",
            "SecurityEvent | where * in (\"a\")",
            "SecurityEvent | where * has_any (\"a\", \"b\")",
        ] {
            assert_eq!(codes_of(not_kusto), [codes::KQL_PARSE_ERROR], "{not_kusto}");
        }
    }

    fn codes_of(source: &str) -> Vec<String> {
        let catalog = Catalog::for_workspace(Profile::Sentinel, source);
        analyze(source, &catalog)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect()
    }

    /// Found by review (#1411): a mistyped operator keeps its "did you mean"
    /// when it parsed whole before the error, as on the old engine; not when
    /// the error is inside it, where the old engine gave the error alone.
    #[test]
    fn a_whole_unknown_operator_before_the_error_keeps_its_suggestion() {
        assert_eq!(
            codes_of("SecurityEvent | summarzie count() by Account"),
            [codes::KQL_PARSE_ERROR, codes::KQL_UNKNOWN_OPERATOR]
        );
        assert_eq!(
            codes_of("SecurityEvent | where Account == \"a\" | summarzie count( by Account"),
            [codes::KQL_PARSE_ERROR]
        );
    }

    /// Found by review (#1411): the hint joins the error when the error comes
    /// after the call, on the next line, and is not given twice.
    #[test]
    fn the_typed_literal_hint_joins_an_error_after_the_call() {
        let source = "print a = datetime(2024-01-01\n| where x";
        let catalog = Catalog::for_workspace(Profile::Sentinel, source);
        let diagnostics = analyze(source, &catalog).diagnostics;
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        assert!(
            diagnostics[0]
                .message
                .contains("'datetime(' starts a typed literal"),
            "{diagnostics:?}"
        );
    }
}
