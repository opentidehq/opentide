//! Every accessor of the typed AST (`src/generated/ast.rs`, written by
//! `cargo xtask codegen` from `esql.ungram`) on the trees of the corpus: each
//! node casts to its typed node, and every child or token an accessor returns
//! is a direct child of that node. The analysis reads the rowan tree, not
//! these accessors, so this is what keeps them right (and measured: the
//! coverage gate counts the generated file).
//!
//! [`ACCESSORS`] lists them; `the_list_names_every_accessor` checks it against
//! the generated file, so a grammar change cannot leave one out.

use opentide_esql::ast;
use opentide_esql::{SyntaxNode, SyntaxToken, syntax_tree};
use opentide_parse::ast::{AstChildren, AstNode};
use std::path::{Path, PathBuf};

/// What an accessor returned: the elements it reached, with their parents.
trait Reached {
    fn reached(self) -> Vec<(rowan::TextRange, Option<SyntaxNode>)>;
}

impl<N: AstNode<Language = opentide_esql::Lang>> Reached for Option<N> {
    fn reached(self) -> Vec<(rowan::TextRange, Option<SyntaxNode>)> {
        self.map(|n| (n.syntax().text_range(), n.syntax().parent()))
            .into_iter()
            .collect()
    }
}

impl<N: AstNode<Language = opentide_esql::Lang>> Reached for AstChildren<N> {
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

macro_rules! lift_node {
    ($($t:ident),* $(,)?) => {
        $(
            impl Lift for Option<ast::$t> {
                type Out = Option<ast::$t>;
                fn lift(self) -> Self {
                    self
                }
            }
            impl Lift for AstChildren<ast::$t> {
                type Out = AstChildren<ast::$t>;
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
        /// is not a direct child of `node`, and the types it cast to.
        fn visit(node: &SyntaxNode, casts: &mut Vec<&'static str>, bad: &mut Vec<String>) {
            $(
                if let Some(typed) = <ast::$t as AstNode>::cast(node.clone()) {
                    casts.push(stringify!($t));
                    assert_eq!(typed.syntax(), node);
                    $(
                        for (range, parent) in typed.$a().lift().reached() {
                            if parent.as_ref() != Some(node) || !node.text_range().contains_range(range) {
                                bad.push(format!("{}::{} at {range:?}", stringify!($t), stringify!($a)));
                            }
                        }
                    )*
                }
            )*
        }
    };
}

accessors! {
        SourceFile => [set_commands, query],
        SetCommand => [set_token, name, eq_token, value, semicolon_token],
        Query => [commands, pipe_token],
        Identifier => [ident_token],
        MapValue => [],
        Command => [],
        SourceCommand => [],
        ProcessingCommand => [],
        FromCommand => [from_token, sources, comma_token, metadata],
        TsCommand => [ts_token, sources, comma_token, metadata],
        RowCommand => [row_token, field_assignment_or_expressions, comma_token],
        ShowCommand => [show_token, info_token],
        PromqlCommand => [promql_token, promql_texts, strings, l_paren_token, r_paren_token],
        ExplainCommand => [explain_token, l_paren_token, query, r_paren_token],
        UnknownCommand => [name, strings, unknown_texts],
        Source => [],
        Metadata => [l_brack_token, metadata_token, metadata_fields, comma_token, r_brack_token],
        IndexPattern => [cluster, colon_token, name, coloncolon_token, selector],
        SourceSubquery => [l_paren_token, source, pipe_token, processing_commands, r_paren_token],
        Cluster => [source_text_token],
        IndexName => [source_text_token, string],
        Selector => [source_text_token],
        String => [string_lit_token],
        SubquerySource => [],
        MetadataField => [source_text_token],
        FieldAssignmentOrExpression => [boolean_expressions, eq_token],
        PromqlText => [promql_word_token],
        WhereCommand => [where_token, condition],
        EvalCommand => [eval_token, field_assignment_or_expressions, comma_token],
        KeepCommand => [keep_token, name_patterns, comma_token],
        DropCommand => [drop_token, name_patterns, comma_token],
        RenameCommand => [rename_token, rename_clauses, comma_token],
        SortCommand => [sort_token, order_expressions, comma_token],
        LimitCommand => [limit_token, boolean_expressions, by_token, comma_token],
        StatsCommand => [stats_token, aggregate_fields, comma_token, by_token, field_assignment_or_expressions],
        InlineStatsCommand => [inline_token, stats_token, inlinestats_token, aggregate_fields, comma_token, by_token, field_assignment_or_expressions],
        DissectCommand => [dissect_token, primary_expressions, command_options, comma_token],
        GrokCommand => [grok_token, primary_expressions, comma_token],
        EnrichCommand => [enrich_token, policy, on_token, match_field, with_token, enrich_with_clauses, comma_token],
        MvExpandCommand => [mv_expand_token, field],
        JoinCommand => [kind, join_token, target, as_token, qualifier, on_token, boolean_expressions, comma_token],
        ChangePointCommand => [change_point_token, boolean_expressions, on_token, as_token, comma_token, by_token],
        CompletionCommand => [completion_token, primary_expressions, eq_token, with_token, identifiers, quoted_identifiers, named_parameters],
        SampleCommand => [sample_token, probability],
        ForkCommand => [fork_token, fork_branches],
        RerankCommand => [rerank_token, target, eq_token, query, on_token, field_assignment_or_expressions, comma_token, named_parameters],
        FuseCommand => [fuse_token, identifier, score_token, key_token, group_token, by_token, comma_token, qualified_names, named_parameterses],
        UriPartsCommand => [uri_parts_token, target, eq_token, input],
        RegisteredDomainCommand => [registered_domain_token, target, eq_token, input],
        UserAgentCommand => [user_agent_token, target, eq_token, input, named_parameters],
        IpLocationCommand => [ip_location_token, target, eq_token, input, named_parameters],
        MetricsInfoCommand => [metrics_info_token],
        TsInfoCommand => [ts_info_token],
        TsCollapseCommand => [ts_collapse_token],
        DedupCommand => [dedup_token],
        MmrCommand => [mmr_token, primary_expressions, on_token, limit_token, named_parameters],
        HighlightCommand => [highlight_token, query, on_token, name_patterns, comma_token, named_parameters],
        DenseVectorCommand => [dense_vector_token, primary_expressions, eq_token, comma_token, named_parameters],
        FillNullCommand => [fillnull_token, value, on_token, name_patterns, comma_token],
        BooleanExpression => [],
        NamePattern => [pattern_parts, dot_token],
        RenameClause => [name_patterns, as_token, eq_token],
        OrderExpression => [key, direction, nulls_token, nulls],
        AggregateField => [boolean_expressions, eq_token, where_token],
        PrimaryExpression => [],
        CommandOption => [name, eq_token, value],
        Constant => [],
        EnrichPolicy => [string, mode, colon_token, name],
        EnrichWithClause => [name_patterns, eq_token],
        EnrichMode => [policy_part_token],
        PolicyName => [policy_part_token],
        QualifiedName => [name_parts, dot_token],
        JoinQualifier => [source_text_token],
        QuotedIdentifier => [quoted_ident_token],
        NamedParameters => [with_token, options],
        MapExpression => [l_curly_token, map_entries, comma_token, r_curly_token],
        ForkBranch => [l_paren_token, processing_commands, pipe_token, r_paren_token],
        CommandName => [command_word_token],
        UnknownText => [unknown_word_token],
        NotExpression => [not_token, operand],
        AndExpression => [boolean_expressions, and_token],
        OrExpression => [boolean_expressions, or_token],
        InExpression => [value_expressions, in_tuple, not_token, in_token, l_paren_token, comma_token, r_paren_token, source_subquery],
        IsNullExpression => [operand, is_token, negated, null_token],
        LikeExpression => [value_expressions, not_token, like_token, rlike_token, l_paren_token, comma_token, r_paren_token],
        MatchExpression => [primary_expressions, colon_token],
        ValueExpression => [],
        InTuple => [l_paren_token, value_expressions, comma_token, r_paren_token],
        Comparison => [left, operator, right],
        OperatorExpression => [],
        UnaryExpression => [operator, operand],
        BinaryExpression => [operator_expressions, operator],
        FunctionCall => [identifier, boolean_expressions, l_paren_token, star, comma_token, map_expression, r_paren_token],
        ParenthesizedExpression => [l_paren_token, boolean_expression, r_paren_token],
        InlineCast => [value, coloncolon_token, type_name],
        TypeName => [identifier],
        Star => [star_token],
        MapEntry => [key, colon_token, value],
        Null => [null_token],
        QualifiedInterval => [value, unit],
        Number => [number_lit_token],
        Boolean => [true_token, false_token],
        Parameter => [param_token],
        Array => [l_brack_token, plus_token, minus_token, numbers, booleans, strings, comma_token, r_brack_token],
        TimeUnit => [ident_token],
        InferenceId => [],
        InLeft => [],
        LikeListItem => [],
        PatternPart => [],
        IdPattern => [id_pattern_token],
        NamePart => [],
}

/// Every `.esql` file under `crates/testdata`, without a corpus file's tag line.
fn corpus() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "esql") {
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
        .map(|path| {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            if path.components().any(|c| c.as_os_str() == "corpus") {
                text.lines().skip(1).collect::<Vec<_>>().join("\n")
            } else {
                text
            }
        })
        .collect()
}

#[test]
fn every_accessor_reaches_a_child_of_its_node() {
    let (mut casts, mut bad, mut nodes) = (Vec::new(), Vec::new(), 0);
    // The forms the corpus does not hold: `null`, a boolean, a unary minus,
    // an enrich mode.
    let extra = "ROW a = null, b = true, c = -x | ENRICH _any:p".to_string();
    for source in corpus().into_iter().chain([extra]) {
        let root = syntax_tree(&source);
        for node in root.descendants() {
            nodes += 1;
            visit(&node, &mut casts, &mut bad);
        }
    }
    assert!(
        bad.is_empty(),
        "{} accessors reached outside their node:\n{}",
        bad.len(),
        bad[..bad.len().min(20)].join("\n")
    );
    assert!(nodes > 5_000, "visited {nodes} nodes");
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
