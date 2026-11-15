//! The ES|QL parser: recursive descent over `opentide-parse`, with a Pratt
//! loop for expressions. It builds the tree `esql.ungram` describes.
//!
//! The lexer reads every word as [`K::WORD`]; ES|QL's keywords are contextual,
//! so a grammar function asks [`at_kw`] where tree-sitter's lexer asked
//! "which tokens are valid here", and re-kinds the word it takes (`bump_as`).

mod commands;
mod expressions;
mod processing;

use crate::lexer;
use crate::syntax::SyntaxKind as K;
use opentide_parse::{Grammar, Input, Parse, Parser, TokenSet, build};

/// The toolkit's view of the language. The nesting limit sits above the
/// floor `deep_queries` holds (1,000 parentheses) by the levels a query's own
/// structure adds.
pub(crate) const GRAMMAR: Grammar = Grammar {
    eof: K::EOF.raw(),
    error: K::ERROR.raw(),
    trivia: K::set(&[K::WHITESPACE, K::COMMENT]),
    max_depth: 1_100,
};

/// Parses `source` into a lossless tree and its syntax errors.
pub(crate) fn parse(source: &str) -> Parse {
    let input = Input::new(source, lexer::lex(source), GRAMMAR);
    let mut p = Parser::new(&input);
    source_file(&mut p);
    build(&input, p.finish())
}

/// `SourceFile = SetCommand* Query?`
fn source_file(p: &mut Parser<'_>) {
    let m = p.start();
    while at_kw(p, K::SET_KW) {
        commands::set_command(p);
    }
    if !p.at_eof() {
        commands::query(p);
    }
    if !p.at_eof() {
        p.err_until("expected `|` or the end of the query", TokenSet::EMPTY);
    }
    m.complete(p, K::SOURCE_FILE.raw());
}

/// Whether the lexer read the current token as text that may be a word.
fn is_word(p: &Parser<'_>) -> bool {
    [K::WORD, K::SOURCE_TEXT, K::POLICY_PART, K::COMMAND_WORD]
        .map(K::raw)
        .contains(&p.current())
}

/// Whether the current token is the keyword `kw`, in any case. A miss or a
/// hit adds `kw` to the kinds the next error expects.
fn at_kw(p: &mut Parser<'_>, kw: K) -> bool {
    let _ = p.at(kw.raw());
    is_word(p)
        && kw
            .keyword_text()
            .is_some_and(|w| p.current_text().eq_ignore_ascii_case(w))
}

/// Whether the `n`th token ahead is the keyword `kw` (not recorded as expected).
fn nth_kw(p: &Parser<'_>, n: usize, kw: K) -> bool {
    kw.keyword_text()
        .is_some_and(|w| p.nth_text(n).eq_ignore_ascii_case(w))
        && [K::WORD, K::SOURCE_TEXT, K::POLICY_PART]
            .map(K::raw)
            .contains(&p.nth(n))
}

/// Takes the keyword `kw` if the parser is at it.
fn eat_kw(p: &mut Parser<'_>, kw: K) -> bool {
    let found = at_kw(p, kw);
    if found {
        p.bump_as(kw.raw());
    }
    found
}

/// Takes the keyword `kw`, or records `expected `kw``.
fn expect_kw(p: &mut Parser<'_>, kw: K) -> bool {
    let found = eat_kw(p, kw);
    if !found {
        p.error(format!("expected `{}`", kw.keyword_text().unwrap_or("")));
    }
    found
}

/// `item (',' item)*`: it stops where an item takes nothing and no comma follows.
fn comma_list(p: &mut Parser<'_>, mut item: impl FnMut(&mut Parser<'_>)) {
    loop {
        item(p);
        if !p.eat(K::COMMA.raw()) {
            break;
        }
    }
}

/// A node that wraps the current token as `kind`.
fn token_node(p: &mut Parser<'_>, token: K, kind: K) {
    let m = p.start();
    p.bump_as(token.raw());
    m.complete(p, kind.raw());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::Lang;
    use opentide_parse::debug_tree;

    fn tree(source: &str) -> (String, usize) {
        let parse = parse(source);
        let errors = parse.errors.len();
        let node = rowan::SyntaxNode::<Lang>::new_root(parse.green);
        assert_eq!(node.to_string(), source, "lossless");
        (debug_tree(&node, |k| format!("{k:?}")), errors)
    }

    fn clean(source: &str) -> String {
        let (tree, errors) = tree(source);
        assert_eq!(errors, 0, "{source}\n{tree}");
        tree
    }

    #[test]
    fn a_pipeline_of_commands_parses_without_errors() {
        for source in [
            "FROM logs-* METADATA _id | WHERE a == 1 AND NOT b IN (1, 2) OR c LIKE \"x*\"",
            "FROM a, b | STATS n = COUNT(*), m = MAX(x) WHERE y > 1 BY h = BUCKET(@timestamp, 1 hour)",
            "ROW a = 1 | EVAL b = a::long + 2 * 3 - -4 | KEEP a*, b.c | SORT b DESC NULLS FIRST | LIMIT 10",
            "FROM a | LOOKUP JOIN idx ON x == y | ENRICH p ON f WITH n = g | RENAME a AS b, c = d",
            "FROM a | FORK (WHERE x | LIMIT 1) (KEEP y) | FUSE RRF | DEDUP",
            "SET a = 1; FROM a | WHERE (x, y) IN (FROM b | KEEP x, y) AND z IS NOT NULL",
            "FROM a | WHERE m : \"q\" AND f(x, {\"k\": [1, 2]}) > ?p AND 5 minutes > 1",
            "FROM a | WEHRE x == 1 | LIMIT 1",
            "PROMQL rate(a[5m]) | LIMIT 1",
            "EXPLAIN (FROM a) | LIMIT 1",
        ] {
            clean(source);
        }
    }

    #[test]
    fn operators_bind_as_the_grammar_says() {
        // A chain of `or` is one flat node; `and` binds tighter; arithmetic under comparison.
        let t = clean("ROW x = a or b or c and d == 1 + 2 * 3");
        assert_eq!(t.matches(" OR_EXPRESSION@").count(), 1, "{t}");
        assert_eq!(t.matches(" AND_EXPRESSION@").count(), 1, "{t}");
        assert_eq!(t.matches("BINARY_EXPRESSION@").count(), 2, "{t}");
        assert_eq!(t.matches("COMPARISON@").count(), 1, "{t}");
    }

    #[test]
    fn broken_queries_have_errors_and_stay_lossless() {
        for source in [
            "FROM",
            "FROM a | WHERE",
            "FROM a | WHERE (a == 1",
            "FROM a | LIMIT",
            "FROM a | KEEP",
            "FROM a | EVAL f(",
            "FROM a | | LIMIT 1",
            "FROM a | STATS x = ",
            "ROW a = [1, 2",
            "PROMQL (rate(x)",
            "FROM a | WHERE (a, b) IN (1, 2)",
            "FROM a | WHERE a == == 1",
        ] {
            let (tree, errors) = tree(source);
            assert!(errors > 0, "{source}\n{tree}");
        }
    }

    #[test]
    fn a_word_is_a_unit_where_no_keyword_is_valid() {
        // tree-sitter lexed a word as a keyword only where the grammar takes it.
        for source in [
            "FROM a | LIMIT 1 LIKE",
            "FROM a | LIMIT 5WITH",
            "FROM a | SAMPLE 1 BY",
        ] {
            let t = clean(source);
            assert!(t.contains("QUALIFIED_INTERVAL@"), "{source}\n{t}");
        }
        let t = clean("FROM a | LIMIT 1 BY x");
        assert!(!t.contains("QUALIFIED_INTERVAL@"), "{t}");
        let t = clean("FROM a | WHERE x > 1 AND y");
        assert!(!t.contains("QUALIFIED_INTERVAL@"), "{t}");
    }

    #[test]
    fn nesting_past_the_limit_is_one_diagnostic() {
        let deep = format!("ROW x = {}1{}", "(".repeat(2_000), ")".repeat(2_000));
        let (_, errors) = tree(&deep);
        assert_eq!(errors, 1);
        let ok = format!("ROW x = {}1{}", "(".repeat(1_000), ")".repeat(1_000));
        clean(&ok);
        let chain = format!("ROW x = {}", vec!["a == 1"; 20_000].join(" OR "));
        clean(&chain);
    }
}
