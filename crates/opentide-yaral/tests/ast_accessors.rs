//! Every accessor of the typed AST (`src/generated/ast.rs`, written by
//! `cargo xtask codegen` from `yaral.ungram`) on the trees of the corpus: each
//! node casts to its typed node, and every child or token an accessor returns
//! is a direct child of that node. The analysis reads the rowan tree, not
//! these accessors, so this is what keeps them right (and measured: the
//! coverage gate counts the generated file).
//!
//! [`ACCESSORS`] lists them; `the_list_names_every_accessor` checks it against
//! the generated file, so a grammar change cannot leave one out.

use opentide_parse::ast::{AstChildren, AstNode};
use opentide_yaral::ast::*;
use opentide_yaral::parse_facts::tree;
use opentide_yaral::{SyntaxNode, SyntaxToken};
use std::path::{Path, PathBuf};

/// What an accessor returned: the elements it reached, with their parents.
trait Reached {
    fn reached(self) -> Vec<(rowan::TextRange, Option<SyntaxNode>)>;
}

impl<N: AstNode<Language = opentide_yaral::Lang>> Reached for Option<N> {
    fn reached(self) -> Vec<(rowan::TextRange, Option<SyntaxNode>)> {
        self.map(|n| (n.syntax().text_range(), n.syntax().parent()))
            .into_iter()
            .collect()
    }
}

impl<N: AstNode<Language = opentide_yaral::Lang>> Reached for AstChildren<N> {
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
        SourceFile => [rule_declarations, search_query],
        RuleDeclaration => [rule_token, rule_name, l_curly_token, sections, r_curly_token],
        SearchQuery => [stages, search_events, sections],
        RuleName => [ident_token],
        Section => [],
        MetaSection => [meta_token, colon_token, meta_entries],
        SetupSection => [setup_token, colon_token, graph_operations, statements],
        EventsSection => [events_token, colon_token, statements],
        MatchSection => [match_token, colon_token, match_clause],
        OutcomeSection => [outcome_token, colon_token, statements],
        ConditionSection => [condition_token, colon_token, statements],
        OptionsSection => [options_token, colon_token, option_entries],
        ExportSection => [export_token, colon_token, statements],
        DedupSection => [dedup_token, colon_token, exprs, comma_token],
        OrderSection => [order_token, colon_token, order_items, comma_token],
        LimitSection => [limit_token, colon_token, integer_token],
        SelectSection => [select_token, colon_token, exprs, comma_token],
        UnselectSection => [unselect_token, colon_token, exprs, comma_token],
        MetaEntry => [meta_key, eq_token, value],
        MetaKey => [ident_token],
        SettingValue => [],
        Literal => [string_token, raw_string_token, regex_lit_token, integer_token, float_token, duration_token, true_token, false_token],
        NameRef => [ident_token],
        OptionEntry => [option_key, eq_token, value],
        OptionKey => [ident_token],
        GraphOperation => [],
        Statement => [],
        GraphJoin => [name, l_paren_token, join, r_paren_token],
        GraphAppend => [graph_append_token, terms],
        Expr => [],
        ArrayExpr => [l_brack_token, exprs, comma_token, r_brack_token],
        MatchClause => [field_refs, comma_token, match_window],
        FieldRef => [],
        MatchWindow => [kind, every_token, first_token, duration_token, integer_token, time_unit, direction, pivot],
        Variable => [variable_token],
        UdmField => [variable, accessors],
        BareField => [root, accessors],
        TimeUnit => [ident_token],
        OrderItem => [value, direction],
        Stage => [stage_token, stage_name, l_curly_token, search_events, sections, r_curly_token],
        SearchEvents => [statements],
        StageName => [ident_token],
        CrossJoin => [cross_token, join_token, variables, comma_token],
        OrExpr => [exprs, or_token],
        AndExpr => [exprs, and_token],
        NotExpr => [not_token, operand],
        Comparison => [left, op, right, nocase_token],
        InExpr => [left, in_token, kind, right, nocase_token],
        BinaryExpr => [exprs, op],
        UnaryExpr => [op, operand],
        OfExpr => [quantifier, of_token, terms],
        ParenExpr => [l_paren_token, expr, r_paren_token],
        QuantifiedField => [quantifier, field],
        CountRef => [count_ref_token],
        FunctionCall => [function_name, l_paren_token, arguments, r_paren_token, nocase_token],
        IfExpr => [if_token, l_paren_token, exprs, comma_token, r_paren_token],
        TableCall => [table, table_dot_token, function, l_paren_token, arguments, r_paren_token],
        ReferenceList => [reference_list_token],
        DataTableColumn => [table, table_dot_token, column],
        WindowBound => [window_start_token, window_end_token],
        Accessor => [],
        Member => [dot_token, field_name_token],
        Index => [index_bracket_token, key, r_brack_token],
        FunctionName => [ident_token, dot_token, field_name_token],
        Arguments => [arguments, comma_token],
        Argument => [],
        NamedArgument => [name, colon_token, value, wildcard],
        ArgumentName => [ident_token, bare_field],
}

/// Every `.yaral` file under `crates/testdata`; a corpus file's tag line is a
/// YARA-L comment, so the text is parsed whole.
fn corpus() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "yaral" || e == "yl2") {
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
