//! The Lucene classic query grammar, as functions over
//! [`opentide_parse::Parser`]. It follows
//! `grammars/tree-sitter-opentide-lucene/grammar.js`: clauses have no
//! precedence, so a run of clauses and operators is one flat n-ary
//! `BooleanQuery`, however long.

use crate::syntax::{SyntaxKind as K, SyntaxNode, lex};
use opentide_parse::{Grammar, Input, Parse, Parser, TokenSet, build, debug_errors, debug_tree};

/// Nesting (`(`) deeper than this is one error. The tree-sitter engine took
/// 10 000 levels; the floor every language keeps is `deep_queries`'
/// `NESTING_CEILING` (1,000), and a level is at most three nodes, far under
/// `MAX_TREE_DEPTH`.
pub(crate) const MAX_DEPTH: u32 = 1_024;

/// Error messages the analysis maps to its own text.
pub(crate) const MISSING_PAREN: &str = "missing `)`";
pub(crate) const MISSING_CLAUSE: &str = "missing a clause";
pub(crate) const MISSING_BOUND: &str = "missing a range bound";
pub(crate) const MISSING_TO: &str = "missing `TO`";
pub(crate) const MISSING_CLOSE: &str = "missing a range closer";
pub(crate) const UNEXPECTED: &str = "unexpected";

/// A token that stands for a term where a clause begins: `&&` and `||` are
/// operators only after a clause.
const TERMS: TokenSet = K::set(&[K::Term, K::AmpAmp, K::PipePipe]);
const FIELD_NAMES: TokenSet = K::set(&[K::Term, K::AmpAmp, K::PipePipe, K::Star, K::WildcardTerm]);
const TERM_QUERIES: TokenSet = K::set(&[
    K::Term,
    K::AmpAmp,
    K::PipePipe,
    K::Star,
    K::WildcardTerm,
    K::BareOperator,
]);
const BODIES: TokenSet = K::set(&[
    K::Term,
    K::AmpAmp,
    K::PipePipe,
    K::Star,
    K::WildcardTerm,
    K::BareOperator,
    K::Phrase,
    K::Regexp,
    K::LParen,
    K::LBracket,
    K::LBrace,
]);
const MODIFIERS: TokenSet = K::set(&[K::Plus, K::Minus, K::NotKw, K::Bang]);
const AND: TokenSet = K::set(&[K::AndKw, K::AmpAmp]);
const OR: TokenSet = K::set(&[K::OrKw, K::PipePipe]);
const BOUNDS: TokenSet = K::set(&[K::RangeTerm, K::Phrase]);
const CLOSERS: TokenSet = K::set(&[K::RBracket, K::RBrace]);

/// Parses `source`.
pub(crate) fn parse(source: &str) -> (SyntaxNode, Parse) {
    let grammar = Grammar {
        eof: K::Eof.raw(),
        error: K::Error.raw(),
        trivia: K::set(&[K::Whitespace]),
        max_depth: MAX_DEPTH,
    };
    let input = Input::new(source, lex(source), grammar);
    let mut p = Parser::new(&input);
    let root = p.start();
    query(&mut p, false);
    root.complete(&mut p, K::SourceFile.raw());
    let parse = build(&input, p.finish());
    (SyntaxNode::new_root(parse.green.clone()), parse)
}

fn at(p: &mut Parser<'_>, kind: K) -> bool {
    p.at(kind.raw())
}

/// `_query`: clauses and operators up to the end, or up to `)` in a group.
fn query(p: &mut Parser<'_>, in_group: bool) {
    let m = p.start();
    let mut clauses = 0usize;
    // Whether an operator was read and a clause must follow.
    let mut pending = false;
    loop {
        if p.at_eof() || (in_group && at(p, K::RParen)) {
            break;
        }
        if clauses > 0 && !pending && (p.at_set(AND) || p.at_set(OR)) {
            conjunction(p);
            pending = true;
        } else if p.at_set(MODIFIERS) || p.at_set(BODIES) {
            clause(p);
            clauses += 1;
            pending = false;
        } else {
            // A stray closer, an operator with no clause before it, `AND` where
            // a clause begins: the token is the error.
            if pending {
                p.error(MISSING_CLAUSE);
                pending = false;
            }
            p.err_and_bump(UNEXPECTED);
        }
    }
    if pending {
        p.error(MISSING_CLAUSE);
    }
    if clauses > 1 {
        m.complete(p, K::BooleanQuery.raw());
    } else {
        m.abandon(p);
    }
}

fn conjunction(p: &mut Parser<'_>) {
    let m = p.start();
    let kind = if p.at_set(AND) { K::And } else { K::Or };
    p.bump();
    m.complete(p, kind.raw());
}

/// A clause with its modifier, if any.
fn clause(p: &mut Parser<'_>) {
    if !p.at_set(MODIFIERS) {
        return clause_body(p);
    }
    let m = p.start();
    let n = p.start();
    let kind = match p.current() {
        k if k == K::Plus.raw() => K::Required,
        k if k == K::Minus.raw() => K::Prohibited,
        _ => K::Not,
    };
    p.bump();
    n.complete(p, kind.raw());
    if p.at_set(BODIES) {
        clause_body(p);
    } else {
        p.error(MISSING_CLAUSE);
    }
    m.complete(p, K::ModifiedClause.raw());
}

/// `_clause`: a field query or a clause body.
fn clause_body(p: &mut Parser<'_>) {
    if p.at_set(FIELD_NAMES) && p.nth(1) == K::Colon.raw() {
        let m = p.start();
        let name = p.start();
        term(p);
        name.complete(p, K::FieldName.raw());
        p.bump();
        if p.at_set(BODIES) {
            body(p);
        } else {
            p.error(MISSING_CLAUSE);
        }
        m.complete(p, K::FieldQuery.raw());
    } else {
        body(p);
    }
}

/// A group, a term, a phrase, a range or a regexp, with its suffixes.
fn body(p: &mut Parser<'_>) {
    let current = p.current();
    if current == K::LParen.raw() {
        group(p);
    } else if current == K::LBracket.raw() || current == K::LBrace.raw() {
        range(p);
    } else if current == K::Regexp.raw() {
        let m = p.start();
        p.bump();
        p.eat(K::Boost.raw());
        m.complete(p, K::RegexpQuery.raw());
    } else if current == K::Phrase.raw() {
        let m = p.start();
        p.bump();
        suffix(p);
        m.complete(p, K::PhraseQuery.raw());
    } else if p.at_set(TERM_QUERIES) {
        let m = p.start();
        term(p);
        suffix(p);
        m.complete(p, K::TermQuery.raw());
    } else {
        p.error(MISSING_CLAUSE);
    }
}

/// A term token; `&&` and `||` are terms here.
fn term(p: &mut Parser<'_>) {
    if p.at_set(TERMS) {
        p.bump_as(K::Term.raw());
    } else {
        p.bump();
    }
}

/// A boost and a fuzzy, in either order, once each.
fn suffix(p: &mut Parser<'_>) {
    if p.eat(K::Boost.raw()) {
        p.eat(K::Fuzzy.raw());
    } else if p.eat(K::Fuzzy.raw()) {
        p.eat(K::Boost.raw());
    }
}

fn group(p: &mut Parser<'_>) {
    if !p.enter() {
        return;
    }
    let m = p.start();
    p.bump();
    query(p, true);
    if at(p, K::RParen) {
        p.bump();
    } else {
        p.error(MISSING_PAREN);
    }
    p.eat(K::Boost.raw());
    m.complete(p, K::Group.raw());
    p.exit();
}

/// `[lower TO upper]`, with `{` and `}` for an open end.
fn range(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump();
    bound(p);
    if !p.eat(K::ToKw.raw()) {
        p.error(MISSING_TO);
    }
    bound(p);
    if p.at_set(CLOSERS) {
        p.bump();
    } else {
        p.error(MISSING_CLOSE);
    }
    p.eat(K::Boost.raw());
    m.complete(p, K::RangeQuery.raw());
}

fn bound(p: &mut Parser<'_>) {
    if p.at_set(BOUNDS) {
        p.bump();
    } else {
        p.error(MISSING_BOUND);
    }
}

/// The tree of `source` and its errors as indented text, for the snapshot
/// tests (`tests/trees.rs`).
pub(crate) fn debug(source: &str) -> String {
    let (root, parse) = parse(source);
    let mut out = debug_tree(&root, |k| format!("{k:?}"));
    // Kind names, not message spellings: several kinds read "a term".
    out.push_str(&debug_errors(&parse.errors, |k| {
        format!("{:?}", K::from_raw(k))
    }));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_parse::{ErrorKind, MAX_TREE_DEPTH};

    #[test]
    fn every_tree_is_lossless() {
        for source in [
            "a AND (b OR c",
            "\\ \"x y:\u{e9}\u{a0}AND\n\tOR",
            "f:[ a TO",
            ")(}{:^~",
            "a:[1 TO 2}^3 -",
            "",
            "   ",
        ] {
            let (root, _) = parse(source);
            assert_eq!(root.text(), source, "{source:?}");
        }
    }

    #[test]
    fn a_chain_is_one_flat_node() {
        let n = 20_000;
        let source = vec!["a:1"; n].join(" OR ");
        let (root, parse) = parse(&source);
        assert!(parse.errors.is_empty());
        assert!(parse.depth < 10, "depth {}", parse.depth);
        let chain = root.first_child().expect("the clause list");
        assert_eq!(chain.kind(), K::BooleanQuery);
        // The clauses and the operators between them.
        assert_eq!(chain.children().count(), 2 * n - 1);
    }

    #[test]
    fn nesting_past_the_limit_is_one_diagnostic_not_an_overflow() {
        for source in [
            "(".repeat(200_000),
            format!("{}a{}", "(".repeat(100_000), ")".repeat(100_000)),
            format!("f:{}a", "(".repeat(100_000)),
        ] {
            let (root, parse) = parse(&source);
            assert_eq!(root.text(), source.as_str());
            let deep: Vec<_> = parse
                .errors
                .iter()
                .filter(|e| matches!(e.kind, ErrorKind::TooDeep { .. }))
                .collect();
            assert_eq!(deep.len(), 1, "{:?}", parse.errors.len());
            assert!(parse.depth < MAX_TREE_DEPTH);
        }
    }

    #[test]
    fn nesting_at_the_limit_parses() {
        let levels = usize::try_from(MAX_DEPTH).expect("fits");
        for source in [
            format!("{}a:1{}", "(".repeat(levels), ")".repeat(levels)),
            format!("a:{}b{}", "(".repeat(levels), ")".repeat(levels)),
        ] {
            let (_, parse) = parse(&source);
            assert!(parse.errors.is_empty(), "{:?}", &parse.errors[..1]);
        }
    }

    #[test]
    fn a_stray_token_is_an_error_and_the_parse_goes_on() {
        let (root, parse) = parse("a ) b AND");
        assert_eq!(root.text(), "a ) b AND");
        assert!(parse.errors.len() >= 2);
    }
}
