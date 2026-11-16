//! Every accessor of the typed AST (`src/generated/ast.rs`, written by
//! `cargo xtask codegen` from `spl.ungram`) on the trees of the corpus: each
//! node casts to its typed node, and every child or token an accessor returns
//! is a direct child of that node. The analysis reads the rowan tree, not
//! these accessors, so this is what keeps them right (and measured: the
//! coverage gate counts the generated file).
//!
//! [`ACCESSORS`] lists them; `the_list_names_every_accessor` checks it against
//! the generated file, so a grammar change cannot leave one out.

use opentide_parse::ast::{AstChildren, AstNode};
use opentide_spl::ast::*;
use opentide_spl::syntax::parse;
use opentide_spl::{SyntaxNode, SyntaxToken};
use std::path::{Path, PathBuf};

/// What an accessor returned: the elements it reached, with their parents.
trait Reached {
    fn reached(self) -> Vec<(rowan::TextRange, Option<SyntaxNode>)>;
}

impl<N: AstNode<Language = opentide_spl::Lang>> Reached for Option<N> {
    fn reached(self) -> Vec<(rowan::TextRange, Option<SyntaxNode>)> {
        self.map(|n| (n.syntax().text_range(), n.syntax().parent()))
            .into_iter()
            .collect()
    }
}

impl<N: AstNode<Language = opentide_spl::Lang>> Reached for AstChildren<N> {
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
        /// is not a direct child of `node`, and the types it cast to.
        fn visit(node: &SyntaxNode, casts: &mut Vec<&'static str>, bad: &mut Vec<String>) {
            $(
                if let Some(typed) = <$t as AstNode>::cast(node.clone()) {
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
        SourceFile => [pipeline],
        Pipeline => [stages, pipe_token],
        Stage => [],
        BareSearch => [search_items],
        SearchCommand => [search_token, search_expression],
        WhereCommand => [where_token, predicate],
        EvalCommand => [eval_token, assignments, comma_token],
        StatsCommand => [stats_token, chart_token, geostats_token, command_options, aggregate_items, macro_calls, comma_token, over_clause, by_clause, chart_where],
        RexCommand => [rex_token, command_options, field_token, comma_token, strs],
        TableCommand => [table_token, field_names, comma_token],
        RenameCommand => [rename_token, rename_items, comma_token],
        FieldsCommand => [fields_token, minus_token, plus_token, field_names, comma_token],
        DedupCommand => [dedup_token, number, dedup_options, field_names, comma_token, sortby_token, sort_items],
        SortCommand => [sort_token, number, command_options, sort_items, comma_token, desc_token, d_token],
        HeadCommand => [head_token, number, command_options],
        TailCommand => [tail_token, number],
        JoinCommand => [join_token, command_options, identifiers, comma_token, subsearch],
        LookupCommand => [lookup_token, command_options, identifiers, strs, macro_calls, lookup_fields, output_token, outputnew_token, comma_token],
        MakemvCommand => [makemv_token, command_options, delim_token, eq_token, strs, identifiers],
        MvexpandCommand => [mvexpand_token, command_options, identifiers, l_paren_token, r_paren_token],
        TstatsCommand => [tstats_token, tstats_preambles, aggregate_items, comma_token, from_token, datamodel_token, eq_token, identifier, str, where_token, search_expression, by_clause],
        FillnullCommand => [fillnull_token, command_options, field_names, comma_token],
        ForeachCommand => [foreach_token, command_options, field_names, comma_token, body],
        SpathCommand => [spath_token, command_options, identifiers, strs, macro_calls, subsearches],
        TojsonCommand => [tojson_token, command_options, field_names, function_calls, comma_token],
        InputlookupCommand => [inputlookup_token, command_options, identifiers, strs, macro_calls, subsearches, where_token, search_expression],
        OutputlookupCommand => [outputlookup_token, command_options, identifiers, strs, macro_calls],
        CatalogCommand => [catalog_command_name, argument_list],
        UnknownCommand => [name, argument_list],
        MacroCall => [macro_token],
        SearchItem => [],
        SearchExpression => [search_items],
        SearchBoolean => [and_token, or_token, not_token],
        SearchGroup => [l_paren_token, search_expression, r_paren_token],
        InClause => [field, in_token, value_list],
        TermClause => [term_token, l_paren_token, term_text, r_paren_token],
        CaseClause => [case_token, l_paren_token, term_text, r_paren_token],
        Subsearch => [l_brack_token, pipeline, r_brack_token],
        FieldValue => [field, operator, value],
        Str => [string_token],
        Glob => [glob_token],
        Identifier => [ident_token, number_token, bool_token, field_word_token, dynamic_name_token, token_name_token, template_name_token, prefix_field_token],
        Number => [number_token],
        SearchWord => [search_word_token, call_word_token, field_word_token],
        FieldRef => [field_target],
        ValueList => [l_paren_token, values, comma_token, r_paren_token],
        Value => [],
        TermText => [term_text_token],
        PrefixClause => [prefix_token, l_paren_token, term_text, r_paren_token],
        FieldValueRhs => [field_value_rhs_item],
        FieldTarget => [],
        FieldValueRhsItem => [],
        Expr => [],
        Assignment => [name, eq_token, value],
        NameOrString => [],
        CommandOption => [name, eq_token, value],
        AggregateItem => [function_calls, identifiers, globs, strs, as_token],
        OverClause => [over_token, identifier, glob, str, prefix_clause, macro_call, subsearch, command_options],
        ByClause => [by_token, identifiers, globs, strs, prefix_clauses, macro_calls, subsearches, command_options, comma_token],
        ChartWhere => [where_token, function_calls, identifiers, numbers, in_token, notin_token, eq_token, neq_token, l_angle_token, r_angle_token, lteq_token, gteq_token],
        FunctionCall => [exprs, prefix_clauses, globs, l_paren_token, r_paren_token, comma_token],
        ChartValue => [],
        AggFunction => [],
        AliasName => [],
        FieldName => [],
        RenameItem => [identifiers, globs, strs, function_calls, comma_token, as_token],
        RenameOld => [],
        DedupOption => [keepevents_token, keepempty_token, consecutive_token, eq_token, boolean, identifier],
        SortItem => [plus_token, minus_token, identifier, function_call],
        Boolean => [bool_token],
        LookupField => [field, lookup_alias],
        LookupAlias => [as_token, name_or_string],
        TstatsPreamble => [],
        TstatsOption => [name, eq_token, value],
        OptionValue => [],
        CatalogCommandName => [catalog_command_word_token],
        ArgumentList => [macro_calls, subsearches, search_booleans, command_options, comparisons, function_calls, strs, identifiers, numbers, globs, search_words, comma_token],
        Comparison => [field, operator, value],
        BinExpr => [exprs, value_lists, or_token, and_token, eqeq_token, neq_token, l_angle_token, r_angle_token, lteq_token, gteq_token, eq_token, like_token, in_token, plus_token, minus_token, dot_token, star_token, slash_token, percent_token],
        UnaryExpr => [operator, expr],
        ParenExpr => [l_paren_token, expr, r_paren_token],
}

/// Every `.spl` file under `crates/testdata`, without a corpus file's tag line.
fn corpus() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "spl") {
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
    for source in corpus() {
        let (root, _) = parse(&source);
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
