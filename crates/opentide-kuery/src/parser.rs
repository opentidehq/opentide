//! Kibana KQL's grammar, as functions over [`opentide_parse::Parser`]. It
//! follows `grammars/tree-sitter-opentide-kuery/grammar.js` (Kibana's
//! `grammar.peggy`): `or` < `and` < `not`; a run of `and` (or `or`) is one
//! flat node, so a 20 000-term chain is not 20 000 levels deep.

use crate::syntax::{SyntaxKind as K, SyntaxNode, lex};
use opentide_parse::{
    Event, Grammar, Input, Parse, Parser, TokenSet, build, debug_errors, debug_tree,
};
use std::cell::RefCell;
use std::rc::Rc;

/// Nesting (`(`, `field:(`, `field:{`) deeper than this is one error. The
/// tree-sitter engine took 10 000 levels; the floor every language keeps is
/// `deep_queries`' `NESTING_CEILING` (1,000), and a level is at most three
/// nodes, far under `MAX_TREE_DEPTH`.
pub(crate) const MAX_DEPTH: u32 = 1_024;

/// Error messages the analysis maps to its own text.
pub(crate) const MISSING_PAREN: &str = "missing `)`";
pub(crate) const MISSING_BRACE: &str = "missing `}`";
pub(crate) const MISSING_VALUE: &str = "missing a value";
pub(crate) const UNEXPECTED: &str = "unexpected";

const WORDISH: TokenSet = K::set(&[K::Word, K::OrKw, K::AndKw, K::NotKw]);
const RANGE_OPS: TokenSet = K::set(&[K::Lt, K::Lte, K::Gt, K::Gte]);
const LITERAL: TokenSet = K::set(&[K::Word, K::QuotedString]);

/// A tree and its parse.
pub(crate) type Parsed = (SyntaxNode, Parse);

/// The masked parse of `source`, shared by [`crate::analyze`],
/// [`crate::fields`] and [`crate::ecs_diagnostics`]: an editor asks all three
/// for the same text, and the last parse on this thread is kept (one per
/// text, epic #1219's one-parse memo).
pub(crate) fn parse_memo(source: &str) -> Rc<Parsed> {
    thread_local! {
        static LAST: RefCell<Option<(String, Rc<Parsed>)>> = const { RefCell::new(None) };
    }
    LAST.with(|last| {
        let mut last = last.borrow_mut();
        if let Some((text, parsed)) = last.as_ref()
            && text == source
        {
            return Rc::clone(parsed);
        }
        let parsed = Rc::new(parse(source, true));
        // A text past the cap is not kept: an idle thread would hold it and
        // its tree until its next query.
        *last = (source.len() <= MEMO_MAX).then(|| (source.to_owned(), Rc::clone(&parsed)));
        parsed
    })
}

/// The largest text [`parse_memo`] keeps, in bytes. Detection queries are a
/// few kilobytes.
pub(crate) const MEMO_MAX: usize = 64 * 1024;

/// Parses `source` (with Kibana's trailing-keyword masking when `mask`).
pub(crate) fn parse(source: &str, mask: bool) -> (SyntaxNode, Parse) {
    let parse = with_events(source, mask, built);
    (SyntaxNode::new_root(parse.green.clone()), parse)
}

/// Whether [`parse`] reports no error. Every error the grammar records is
/// one of the tree's, so a text with one is rejected without building the
/// tree (ADR 0014 §4). A text with none is built, as a backstop for the
/// errors only the build finds (a tree too deep, unbalanced events); the
/// grammar's own depth limit fires before either today.
pub(crate) fn accepts(source: &str, mask: bool) -> bool {
    with_events(source, mask, |input, events| {
        !events.iter().any(|e| matches!(e, Event::Error { .. }))
            && built(input, events).errors.is_empty()
    })
}

#[cfg(test)]
thread_local! {
    /// The trees built on this thread: [`trees_built`].
    static TREES_BUILT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many trees this thread has built (ADR 0014 §7).
#[cfg(test)]
pub(crate) fn trees_built() -> usize {
    TREES_BUILT.get()
}

#[inline]
fn built(input: &Input<'_>, events: Vec<Event>) -> Parse {
    #[cfg(test)]
    TREES_BUILT.set(TREES_BUILT.get() + 1);
    build(input, events)
}

/// `f` of the grammar's events over `source`, before the tree is built.
#[inline]
fn with_events<R>(source: &str, mask: bool, f: impl FnOnce(&Input<'_>, Vec<Event>) -> R) -> R {
    let grammar = Grammar {
        eof: K::Eof.raw(),
        error: K::Error.raw(),
        trivia: K::set(&[K::Whitespace]),
        max_depth: MAX_DEPTH,
    };
    let input = Input::new(source, lex(source, mask), grammar);
    let mut p = Parser::new(&input);
    let root = p.start();
    if !p.at_eof() {
        query(&mut p);
    }
    // What follows a complete query cannot continue it (KQL has no implicit
    // `and`): skip a token, and read on as tree-sitter's recovery does.
    at(&mut p, K::Eof);
    while !p.at_eof() {
        p.err_and_bump(UNEXPECTED);
        let next = p.current();
        if next == K::LParen.raw() || next == K::QuotedString.raw() || WORDISH.contains(next) {
            query(&mut p);
        }
    }
    root.complete(&mut p, K::SourceFile.raw());
    let events = p.finish();
    f(&input, events)
}

fn at(p: &mut Parser<'_>, kind: K) -> bool {
    p.at(kind.raw())
}

/// `_query`: `or` chains of `and` chains of `not`/sub-queries.
fn query(p: &mut Parser<'_>) {
    chain(p, K::OrKw, K::OrQuery, |p| {
        chain(p, K::AndKw, K::AndQuery, unary);
    });
}

/// `operand (op operand)*` as one node of `kind` when an `op` follows.
fn chain(p: &mut Parser<'_>, op: K, kind: K, operand: fn(&mut Parser<'_>)) {
    let m = p.start();
    operand(p);
    if !at(p, op) {
        m.abandon(p);
        return;
    }
    while at(p, op) {
        p.bump();
        operand(p);
    }
    m.complete(p, kind.raw());
}

fn unary(p: &mut Parser<'_>) {
    if at(p, K::NotKw) {
        let m = p.start();
        p.bump();
        sub_query(p);
        m.complete(p, K::NotQuery.raw());
    } else {
        sub_query(p);
    }
}

/// `_sub_query`: a group, or a literal that may turn out to be a field.
fn sub_query(p: &mut Parser<'_>) {
    if at(p, K::LParen) {
        if !p.enter() {
            return;
        }
        let m = p.start();
        p.bump();
        query(p);
        close(p, K::RParen, MISSING_PAREN);
        m.complete(p, K::Group.raw());
        p.exit();
        return;
    }
    let outer = p.start();
    let field = p.start();
    if !literal(p) {
        field.abandon(p);
        outer.abandon(p);
        p.error(MISSING_VALUE);
        return;
    }
    if at(p, K::Colon) {
        field.complete(p, K::Field.raw());
        p.bump();
        if at(p, K::LBrace) {
            if p.enter() {
                p.bump();
                query(p);
                close(p, K::RBrace, MISSING_BRACE);
                p.exit();
            }
            outer.complete(p, K::NestedQuery.raw());
        } else {
            value(p);
            outer.complete(p, K::FieldValueExpression.raw());
        }
    } else if p.at_set(RANGE_OPS) {
        field.complete(p, K::Field.raw());
        p.bump();
        if !literal(p) {
            p.error(MISSING_VALUE);
        }
        outer.complete(p, K::RangeExpression.raw());
    } else {
        field.abandon(p);
        outer.complete(p, K::ValueExpression.raw());
    }
}

/// `)` or `}`; anything else before it is one error node.
fn close(p: &mut Parser<'_>, kind: K, missing: &str) {
    if at(p, kind) {
        p.bump();
        return;
    }
    if p.at_eof() {
        p.error(missing);
        return;
    }
    p.err_until(UNEXPECTED, K::set(&[kind]));
    if at(p, kind) {
        p.bump();
    } else {
        p.error(missing);
    }
}

/// `_literal`: a quoted string, or a run of words (`and`/`or` end it, `not`
/// does not: Kibana's grammar has no keyword there).
fn literal(p: &mut Parser<'_>) -> bool {
    // What fits here, for an error's expected set: a word or a quoted string
    // (`and`, `or` and `not` are words here, so they are not named).
    p.at_set(LITERAL);
    // A character no token takes (a lone `\`, an unclosed `"`) is an error
    // node; the literal may follow it.
    while p.current() == K::ErrorToken.raw() {
        p.err_and_bump(UNEXPECTED);
    }
    if p.current() == K::QuotedString.raw() {
        p.bump();
        return true;
    }
    if !WORDISH.contains(p.current()) {
        return false;
    }
    let m = p.start();
    p.bump_as(K::Word.raw());
    // A further word continues the value: valid, but not worth naming in an
    // error's expected set, so the lookahead is not recorded.
    while matches!(p.current(), k if k == K::Word.raw() || k == K::NotKw.raw()) {
        p.bump_as(K::Word.raw());
    }
    m.complete(p, K::UnquotedLiteral.raw());
    true
}

/// After `field:`: a `( list )` or a literal.
fn value(p: &mut Parser<'_>) {
    if at(p, K::LParen) {
        value_list(p);
    } else if !literal(p) {
        p.error(MISSING_VALUE);
    }
}

fn value_list(p: &mut Parser<'_>) {
    if !p.enter() {
        return;
    }
    let m = p.start();
    p.bump();
    chain(p, K::OrKw, K::OrList, |p| {
        chain(p, K::AndKw, K::AndList, list_unary);
    });
    close(p, K::RParen, MISSING_PAREN);
    m.complete(p, K::ValueList.raw());
    p.exit();
}

fn list_unary(p: &mut Parser<'_>) {
    let m = at(p, K::NotKw).then(|| {
        let m = p.start();
        p.bump();
        m
    });
    if at(p, K::LParen) {
        value_list(p);
    } else if !literal(p) {
        p.error(MISSING_VALUE);
    }
    if let Some(m) = m {
        m.complete(p, K::NotList.raw());
    }
}

/// The tree of `source` and its errors as indented text, for the snapshot
/// tests (`tests/trees.rs`).
pub(crate) fn debug(source: &str) -> String {
    let (root, parse) = parse(source, true);
    let mut out = debug_tree(&root, |k| format!("{k:?}"));
    out.push_str(&debug_errors(&parse.errors, |k| {
        K::from_raw(k).describe().to_owned()
    }));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::Kuery;
    use opentide_parse::{ErrorKind, MAX_TREE_DEPTH};

    /// The texts of the corpus and the external sets, each cut at every
    /// character: valid and broken queries alike.
    fn texts() -> Vec<String> {
        let testdata = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata");
        let mut out = Vec::new();
        for dir in [
            "corpus/kuery",
            "conformance/external/kuery-opensearch-dashboards",
        ] {
            let mut dirs = vec![testdata.join(dir)];
            while let Some(dir) = dirs.pop() {
                for path in std::fs::read_dir(&dir)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|e| e.path())
                {
                    if path.is_dir() {
                        dirs.push(path);
                    } else if let Ok(text) = std::fs::read_to_string(&path) {
                        out.extend(text.lines().map(str::to_owned).take(200));
                        out.push(text);
                    }
                }
            }
        }
        let cut: Vec<String> = out
            .iter()
            .filter(|t| t.len() < 400)
            .flat_map(|t| {
                t.char_indices()
                    .map(|(i, _)| t[..i].to_owned())
                    .collect::<Vec<_>>()
            })
            .collect();
        out.extend(cut);
        out
    }

    /// `accepts` is `parse`'s verdict, on every text and at the grammar's
    /// nesting limit (its own depth error, an error event, fires there before
    /// the build could find a tree too deep).
    #[test]
    fn accepts_is_the_parse_without_errors() {
        let mut sources = texts();
        for depth in [MAX_DEPTH - 1, MAX_DEPTH, MAX_DEPTH + 1] {
            let depth = depth as usize;
            sources.push(format!("{}a:1{}", "(".repeat(depth), ")".repeat(depth)));
        }
        let (mut accepted, mut rejected) = (0, 0);
        for source in &sources {
            let expected = parse(source, false).1.errors.is_empty();
            assert_eq!(accepts(source, false), expected, "{source:?}");
            if expected {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        assert!(
            accepted > 100 && rejected > 100,
            "{accepted} accepted, {rejected} rejected"
        );
    }

    /// A rejected text builds no tree through the public `parses` (ADR 0014
    /// §7): the other engine asks it of every query its own grammar rejects.
    #[test]
    fn a_rejected_text_builds_no_tree() {
        let before = trees_built();
        assert!(!crate::parses("a:1 and (b or c"));
        assert_eq!(trees_built() - before, 0);
        assert!(crate::parses("a:1 and (b or c)"));
        assert_eq!(trees_built() - before, 1);
    }

    #[test]
    fn every_tree_is_lossless() {
        for source in [
            "a:1 and (b or c",
            "\\ \"x y:\u{e9}\u{a0}and\n\tor",
            "f:{ a:(b or",
            ")(}{:<<=",
            "",
            "   ",
        ] {
            let (root, _) = parse(source, true);
            assert_eq!(root.text(), source, "{source:?}");
        }
    }

    #[test]
    fn a_chain_is_one_flat_node() {
        let n = 20_000;
        let source = vec!["a:1"; n].join(" or ");
        let (root, parse) = parse(&source, true);
        assert!(parse.errors.is_empty());
        assert!(parse.depth < 10, "depth {}", parse.depth);
        let chain = root.first_child().expect("the or chain");
        assert_eq!(chain.kind(), K::OrQuery);
        assert_eq!(chain.children().count(), n);
    }

    #[test]
    fn nesting_past_the_limit_is_one_diagnostic_not_an_overflow() {
        for source in [
            "(".repeat(200_000),
            format!("{}a{}", "(".repeat(100_000), ")".repeat(100_000)),
            format!("f:{}a", "(".repeat(100_000)),
            "a:{".repeat(50_000),
        ] {
            let (root, parse) = parse(&source, true);
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
            format!("{}a:1{}", "a:{".repeat(levels), "}".repeat(levels)),
        ] {
            let (_, parse) = parse(&source, true);
            assert!(parse.errors.is_empty(), "{:?}", &parse.errors[..1]);
        }
    }

    #[test]
    fn the_language_maps_its_kinds_both_ways() {
        use rowan::Language;
        for k in [K::Whitespace, K::Group, K::Error] {
            assert_eq!(Kuery::kind_from_raw(Kuery::kind_to_raw(k)), k);
        }
    }
}
