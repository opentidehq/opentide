//! Every accessor of the typed AST (`src/generated/ast.rs`, written by
//! `cargo xtask codegen` from `kql.ungram`) on the trees of the corpus: each
//! node casts to its typed node, and every child or token an accessor returns
//! is a direct child of that node. The analysis reads the rowan tree, not
//! these accessors, so this is what keeps them right (and measured: the
//! coverage gate counts the generated file).
//!
//! [`ACCESSORS`] lists them; `the_list_names_every_accessor` checks it against
//! the generated file, so a grammar change cannot leave one out.

use opentide_kql::ast::*;
use opentide_kql::inspect::tree;
use opentide_kql::{SyntaxNode, SyntaxToken};
use opentide_parse::ast::{AstChildren, AstNode};
use std::path::{Path, PathBuf};

/// What an accessor returned: the elements it reached, with their parents.
trait Reached {
    fn reached(self) -> Vec<(rowan::TextRange, Option<SyntaxNode>)>;
}

impl<N: AstNode<Language = opentide_kql::Lang>> Reached for Option<N> {
    fn reached(self) -> Vec<(rowan::TextRange, Option<SyntaxNode>)> {
        self.map(|n| (n.syntax().text_range(), n.syntax().parent()))
            .into_iter()
            .collect()
    }
}

impl<N: AstNode<Language = opentide_kql::Lang>> Reached for AstChildren<N> {
    fn reached(self) -> Vec<(rowan::TextRange, Option<SyntaxNode>)> {
        self.map(|n| (n.syntax().text_range(), n.syntax().parent()))
            .collect()
    }
}

/// A token is not an `AstNode`: its own impl, through a wrapper.
struct Token(Option<SyntaxToken>);

impl Reached for Token {
    fn reached(self) -> Vec<(rowan::TextRange, Option<SyntaxNode>)> {
        self.0
            .map(|t| (t.text_range(), t.parent()))
            .into_iter()
            .collect()
    }
}

/// Lifts a token accessor's `Option<SyntaxToken>` into [`Token`]; a node
/// accessor's result passes through.
trait Lift {
    type Out: Reached;
    fn lift(self) -> Self::Out;
}

impl Lift for Option<SyntaxToken> {
    type Out = Token;
    fn lift(self) -> Token {
        Token(self)
    }
}

/// A repeated choice of tokens: every one it returned.
struct Tokens(Vec<SyntaxToken>);

impl Reached for Tokens {
    fn reached(self) -> Vec<(rowan::TextRange, Option<SyntaxNode>)> {
        self.0
            .into_iter()
            .map(|t| (t.text_range(), t.parent()))
            .collect()
    }
}

impl Lift for Vec<SyntaxToken> {
    type Out = Tokens;
    fn lift(self) -> Tokens {
        Tokens(self)
    }
}

macro_rules! lift_node {
    ($($t:ident),* $(,)?) => {
        $(
            impl Lift for Option<$t> {
                type Out = Option<$t>;
                fn lift(self) -> Self {
                    self
                }
            }
            impl Lift for AstChildren<$t> {
                type Out = AstChildren<$t>;
                fn lift(self) -> Self {
                    self
                }
            }
        )*
    };
}

macro_rules! accessors {
    ($($t:ident => [$($a:ident),* $(,)?]),* $(,)?) => {
        lift_node!($($t),*);

        /// Every typed node and its accessors, as `cargo xtask codegen` wrote them.
        const ACCESSORS: &[(&str, &[&str])] = &[$((stringify!($t), &[$(stringify!($a)),*])),*];

        /// Casts `node` to every typed node that takes it and calls each
        /// accessor; returns `(type, accessor, problem)` for any element that
        /// is not a direct child of `node`, and the types it cast to. With
        /// `unreached`, also the token children no accessor of a typed node
        /// returns ([`unreached_tokens`]).
        fn visit(
            node: &SyntaxNode,
            casts: &mut Vec<&'static str>,
            bad: &mut Vec<String>,
            mut unreached: Option<&mut Vec<String>>,
        ) {
            $(
                if let Some(typed) = <$t as AstNode>::cast(node.clone()) {
                    casts.push(stringify!($t));
                    assert_eq!(typed.syntax(), node);
                    // What each accessor returned; a choice of nodes (an
                    // enum) has no accessors of its own.
                    let results: Vec<(&str, Vec<(rowan::TextRange, Option<SyntaxNode>)>)> =
                        vec![$((stringify!($a), typed.$a().lift().reached())),*];
                    for (accessor, reached) in &results {
                        for (range, parent) in reached {
                            if parent.as_ref() != Some(node) || !node.text_range().contains_range(*range) {
                                bad.push(format!("{}::{accessor} at {range:?}", stringify!($t)));
                            }
                        }
                    }
                    if let Some(out) = unreached.as_deref_mut().filter(|_| !results.is_empty()) {
                        let reached: Vec<rowan::TextRange> =
                            results.iter().flat_map(|(_, r)| r.iter().map(|(range, _)| *range)).collect();
                        out.extend(unreached_tokens(stringify!($t), node, &reached));
                    }
                }
            )*
        }
    };
}

accessors! {
        SourceFile => [let_statements, query_parameters_statements, query, control_command],
        LetStatement => [let_token, name, eq_token, value, semicolon_token],
        QueryParametersStatement => [declare_token, keyword, l_paren_token, parameters, comma_token, r_paren_token, semicolon_token],
        Query => [body],
        ControlCommand => [dot_token, name, ident_token],
        LetValue => [],
        Parameter => [name, colon_token, r#type, eq_token, default],
        Expr => [],
        TabularExpression => [tabular_source, pipe_token, tabular_operators],
        FunctionDefinition => [l_paren_token, parameters, comma_token, r_paren_token, l_curly_token, let_statements, body, semicolon_token, r_curly_token],
        Type => [name, table_type],
        TableType => [l_paren_token, star_token, table_columns, comma_token, r_paren_token],
        TableColumn => [name, colon_token, r#type],
        TabularSource => [tabular_primary],
        TabularOperator => [],
        TabularPrimary => [],
        TableRef => [l_brack_token, table, r_brack_token],
        QualifiedTable => [function_calls, dot_token, table_ref, table_pattern],
        ParenTabular => [l_paren_token, tabular_expression, r_paren_token],
        PrintOperator => [print_token, column_items, comma_token],
        UnionOperator => [union_token, operator_options, union_legs, comma_token],
        DatatableExpression => [datatable_token, l_paren_token, datatable_columns, comma_token, r_paren_token, l_brack_token, exprs, r_brack_token],
        ExternaldataExpression => [name, operator_options, l_paren_token, datatable_columns, comma_token, r_paren_token, l_brack_token, exprs, r_brack_token, with_token],
        RangeOperator => [range_token, column, from_token, from, to_token, to, step_token, step],
        FunctionCall => [name, l_paren_token, arguments, comma_token, r_paren_token],
        MaterializeExpression => [materialize_token, l_paren_token, body, r_paren_token],
        SearchSource => [name, operator_options, in_token, l_paren_token, table, table_patterns, comma_token, r_paren_token, where_token, predicate, find_project],
        TablePattern => [pieces],
        OperatorOption => [name, eq_token, value],
        FindProject => [project_token, find_columns, comma_token, minus_token, smart],
        FindColumn => [name, colon_token, r#type],
        DatatableColumn => [name, colon_token, r#type],
        OptionValue => [sign, value],
        MvOption => [name, eq_token, value],
        HintOption => [name, eq_token, value],
        WhereOperator => [where_token, predicate],
        FilterOperator => [filter_token, predicate],
        ProjectOperator => [project_token, column_items, comma_token],
        ProjectAwayOperator => [keyword, column_refs, comma_token],
        ProjectRenameOperator => [keyword, rename_items, comma_token],
        ProjectKeepOperator => [keyword, column_refs, comma_token],
        ProjectReorderOperator => [keyword, reorder_items, comma_token],
        ExtendOperator => [extend_token, column_items, comma_token],
        SummarizeOperator => [summarize_token, hint_options, column_items, comma_token, by_token],
        JoinOperator => [join_token, operator_options, tabular_source, on_token, exprs, comma_token],
        ParseOperator => [parse_token, operator_options, column, with_token, parse_parts],
        ParseWhereOperator => [keyword, operator_options, column, with_token, parse_parts],
        ParseKvOperator => [keyword, args, as_token, l_paren_token, datatable_columns, comma_token, r_paren_token, with_token, operator_options],
        LookupOperator => [lookup_token, operator_options, tabular_source, on_token, exprs, comma_token],
        TakeOperator => [take_token, count],
        LimitOperator => [limit_token, count],
        TopOperator => [top_token, count, by_token, sort_items, comma_token],
        CountOperator => [count_token],
        MvExpandOperator => [name, mv_options, mv_expand_items, comma_token, limit_token, limit],
        MvApplyOperator => [keyword, mv_options, mv_expand_items, comma_token, limit_token, limit, on_token, l_paren_token, subquery, r_paren_token],
        MakeSeriesOperator => [keyword, mv_options, series_aggregates, comma_token, on_token, column_items, from_token, to_token, step_token, in_token, by_token],
        EvaluateOperator => [evaluate_token, hint_options, plugin],
        SortOperator => [name, by_token, sort_items, comma_token],
        DistinctOperator => [distinct_token, hint_options, star_arg, column_items, comma_token],
        RenderOperator => [render_token, kind, operator_options, named_arguments, render_with],
        TopNestedOperator => [top_nested_clauses, comma_token],
        SampleDistinctOperator => [keyword, hint_options, count, of_token, column],
        ForkOperator => [fork_token, fork_branches],
        FacetOperator => [facet_token, by_token, columns, comma_token, with_token, l_paren_token, subquery, r_paren_token, operator],
        PartitionOperator => [partition_token, hint_options, by_token, column, in_token, expr, l_paren_token, subquery, r_paren_token, l_curly_token, tabular_expression, r_curly_token],
        ScanOperator => [scan_token, operator_options, order_token, by_token, sort_items, comma_token, partition_token, exprs, declare_token, l_paren_token, parameters, r_paren_token, with_token, scan_steps],
        SerializeOperator => [serialize_token, column_items, comma_token],
        AsOperator => [as_token, hint_options, name],
        TopHittersOperator => [keyword, count, of_token, value, top_hitters_by],
        ReduceOperator => [reduce_token, operator_options, by_token, value, with_token, comma_token],
        SearchOperator => [search_token, operator_options, in_token, l_paren_token, table, table_patterns, comma_token, r_paren_token, predicate],
        MakeGraphOperator => [keyword, source, make_graph_arrow, target, make_graph_nodes, node_id, make_graph_partition],
        GraphMatchOperator => [keyword, operator_options, graph_pattern, where_token, predicate, graph_project],
        GraphShortestPathsOperator => [keyword, operator_options, graph_pattern, where_token, predicate, graph_project],
        GraphToTableOperator => [keyword, graph_to_table_items, comma_token],
        GraphMarkComponentsOperator => [keyword, operator_options],
        KeywordOperator => [name, args],
        UnknownOperator => [name, args],
        Subquery => [tabular_operators, pipe_token],
        ColumnItem => [],
        ColumnRef => [],
        ReorderItem => [column_ref, order],
        RenameItem => [new, eq_token, old],
        NameRef => [name],
        ColumnPattern => [pieces],
        Assignment => [name, eq_token, value],
        TupleAssignment => [name_tuple, eq_token, value],
        NameTuple => [l_paren_token, name_refs, comma_token, r_paren_token],
        UnionLeg => [],
        ParsePart => [],
        ParsePiece => [piece],
        ParseColumn => [name, colon_token, r#type],
        SortItem => [expr, order, nulls_token, nulls],
        MvExpandItem => [column_item, to_token, typeof_token, l_paren_token, r#type, r_paren_token],
        SeriesAggregate => [column_item, series_default],
        SeriesDefault => [default_token, eq_token, expr],
        StarArg => [star_token],
        NamedArgument => [name, eq_token, value],
        RenderWith => [with_token, l_paren_token, render_properties, comma_token, r_paren_token],
        RenderProperty => [],
        TopNestedClause => [keyword, count, top_nested_of, top_nested_others, top_nested_by],
        TopNestedOf => [of_token, column_item],
        TopNestedOthers => [with_token, others_token, eq_token, expr],
        TopNestedBy => [by_token, column_item, order, nulls_token, nulls],
        ForkBranch => [name, eq_token, l_paren_token, subquery, r_paren_token],
        ScanStep => [step_token, name, optional_token, output_token, eq_token, output, colon_token, predicate, fat_arrow_token, assignments, comma_token, semicolon_token],
        TopHittersBy => [by_token, sum],
        MakeGraphArrow => [open, close, head],
        MakeGraphNodes => [with_token, make_graph_node_tables, comma_token],
        MakeGraphPartition => [keyword, minus_token, by_token, column, l_paren_token, subquery, r_paren_token],
        MakeGraphNodeTable => [tabular_source, on_token, key],
        GraphPattern => [graph_paths, comma_token],
        GraphProject => [project_token, column_items, comma_token],
        GraphPath => [graph_nodes, graph_edges],
        GraphNode => [l_paren_token, name, r_paren_token],
        GraphEdge => [backward, open, l_brack_token, name, graph_range, r_brack_token, close, forward],
        GraphRange => [star_token, min, dotdot_token, max],
        GraphToTableItem => [kind, as_token, alias, operator_options],
        OrExpr => [exprs, or_token],
        AndExpr => [exprs, and_token],
        NotExpr => [not_token, operand],
        ComparisonExpr => [lhs, op, matches_token, regex_token, rhs],
        InExpr => [lhs, op, set],
        BetweenExpr => [lhs, op, range],
        AdditiveExpr => [exprs, op],
        MultiplicativeExpr => [exprs, op],
        UnaryExpr => [op, operand],
        MemberExpr => [object, dot_token, member],
        IndexExpr => [object, dot_token, l_brack_token, index, r_brack_token],
        ToscalarExpr => [toscalar_token, l_paren_token, body, r_paren_token],
        ParenExpr => [l_paren_token, expr, r_paren_token],
        Literal => [value],
        DynamicLiteral => [dynamic_token, l_paren_token, json_value, r_paren_token],
        StarExpr => [star_token],
        ExpressionList => [l_paren_token, exprs, comma_token, tabular_expression, r_paren_token],
        Range => [l_paren_token, from, dotdot_token, to, r_paren_token],
        Argument => [],
        JsonValue => [],
        JsonArray => [l_brack_token, json_values, comma_token, r_brack_token],
        JsonObject => [l_curly_token, json_properties, comma_token, r_curly_token],
        JsonScalar => [minus_token, value],
        JsonProperty => [key, colon_token, value],
}

/// Every `.kql` file under `crates/testdata`; a corpus file's tag line is a
/// KQL comment, so the text is parsed whole.
fn corpus() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "kql") {
                out.push(path);
            }
        }
    }
    let mut paths = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut paths,
    );
    paths.sort();
    paths
        .iter()
        .map(|path| std::fs::read_to_string(path).unwrap_or_default())
        .collect()
}

/// The direct token children of `node` (blanks, comments and error tokens
/// aside) whose kind no accessor of its typed node `ty` returned: a token
/// the grammar puts there that the typed AST cannot reach (#1454: a
/// labelled optional choice of tokens read its first token only, so
/// `desc` was out of reach). By kind, so that a second `,` of a list is
/// reached through the accessor that returns the first.
fn unreached_tokens(ty: &str, node: &SyntaxNode, reached: &[rowan::TextRange]) -> Vec<String> {
    let tokens: Vec<SyntaxToken> = node
        .children_with_tokens()
        .filter_map(rowan::NodeOrToken::into_token)
        .collect();
    let kind = |t: &SyntaxToken| format!("{:?}", t.kind());
    let reached: Vec<String> = tokens
        .iter()
        .filter(|t| reached.contains(&t.text_range()))
        .map(kind)
        .collect();
    tokens
        .iter()
        .filter(|t| !matches!(kind(t).as_str(), "WHITESPACE" | "COMMENT" | "ERROR_TOKEN"))
        .filter(|t| !reached.contains(&kind(t)))
        .map(|t| format!("{ty}: `{}` ({}) at {:?}", t.text(), kind(t), t.text_range()))
        .collect()
}

/// Whether the tree holds no error node or token: there every token is
/// where the grammar puts it.
fn is_clean(root: &SyntaxNode) -> bool {
    !root
        .descendants_with_tokens()
        .any(|e| format!("{:?}", e.kind()).starts_with("ERROR"))
}

#[test]
fn every_accessor_reaches_a_child_of_its_node() {
    let (mut casts, mut bad, mut nodes) = (Vec::new(), Vec::new(), 0);
    let (mut unreached, mut clean_trees) = (Vec::new(), 0);
    for source in corpus() {
        let root = tree(&source);
        let clean = is_clean(&root);
        clean_trees += usize::from(clean);
        for node in root.descendants() {
            nodes += 1;
            visit(&node, &mut casts, &mut bad, clean.then_some(&mut unreached));
        }
    }
    assert!(
        bad.is_empty(),
        "{} accessors reached outside their node:\n{}",
        bad.len(),
        bad[..bad.len().min(20)].join("\n")
    );
    assert!(nodes > 5_000, "visited {nodes} nodes");
    // Every token child of a tree without errors is reachable through some
    // accessor of its node.
    unreached.sort_unstable();
    unreached.dedup_by(|a, b| a.split(" at ").next() == b.split(" at ").next());
    assert!(
        unreached.is_empty(),
        "{} token kinds no accessor reaches (in {clean_trees} trees without errors):\n{}",
        unreached.len(),
        unreached[..unreached.len().min(20)].join("\n")
    );
    // Every node kind of the ungram occurs in the corpus, and casts.
    casts.sort_unstable();
    casts.dedup();
    let missing: Vec<_> = ACCESSORS
        .iter()
        .map(|(t, _)| *t)
        .filter(|t| !casts.contains(t))
        .collect();
    assert!(missing.is_empty(), "no corpus tree has a {missing:?}");
}

#[test]
fn the_list_names_every_accessor() {
    let generated = include_str!("../src/generated/ast.rs");
    let mut expected = Vec::new();
    let mut current: Option<&str> = None;
    for line in generated.lines() {
        if let Some(rest) = line
            .strip_prefix("pub struct ")
            .or_else(|| line.strip_prefix("pub enum "))
        {
            expected.push((rest.trim_end_matches(" {").to_string(), Vec::new()));
        } else if let Some(rest) = line.strip_prefix("impl ") {
            current = rest.strip_suffix(" {").filter(|t| !t.contains(' '));
        } else if line == "}" {
            current = None;
        } else if let (Some(t), Some(rest)) = (current, line.trim_start().strip_prefix("pub fn ")) {
            let name = rest.split('(').next().unwrap_or_default().to_string();
            if let Some((_, fns)) = expected.iter_mut().find(|(n, _)| n == t) {
                fns.push(name);
            }
        }
    }
    let listed: Vec<(String, Vec<String>)> = ACCESSORS
        .iter()
        .map(|(t, fns)| {
            (
                (*t).to_string(),
                fns.iter().map(|f| (*f).to_string()).collect(),
            )
        })
        .collect();
    assert_eq!(
        listed, expected,
        "regenerate the list from src/generated/ast.rs"
    );
}
