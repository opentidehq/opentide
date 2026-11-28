//! The Lucene classic query grammar, as functions over
//! [`opentide_parse::Parser`]. It follows
//! `grammars/tree-sitter-opentide-lucene/grammar.js`: clauses have no
//! precedence, so a run of clauses and operators is one flat n-ary
//! `BooleanQuery`, however long.

use crate::syntax::{SyntaxKind as K, SyntaxNode, lex};
use opentide_parse::{
    Event, Grammar, Input, Marker, Parse, Parser, TokenSet, build, debug_errors, debug_tree,
};

/// Nesting (`(`) deeper than this is one error. The tree-sitter engine took
/// 10 000 levels; the floor every language keeps is `deep_queries`'
/// `NESTING_CEILING` (1,000). A level opens at most four nodes (a group, its
/// clause list, a modified clause and a field query), so the tree stays
/// under `MAX_TREE_DEPTH` (4,096) at this limit: at 1,024 levels a valid
/// query got `TreeTooDeep` instead.
pub(crate) const MAX_DEPTH: u32 = 1_000;

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
    let parse = with_events(source, built);
    (SyntaxNode::new_root(parse.green.clone()), parse)
}

/// Whether [`parse`] reports no error. Every error the grammar records is
/// one of the tree's, so a text with one is rejected without building the
/// tree (ADR 0014 §4). A text with none is built, as a backstop for the
/// errors only the build finds (a tree too deep, unbalanced events); the
/// grammar's own depth limit fires before either today.
pub(crate) fn accepts(source: &str) -> bool {
    with_events(source, |input, events| {
        !events.iter().any(|e| matches!(e, Event::Error { .. }))
            && built(input, events).errors.is_empty()
    })
}

/// `f` of the grammar's events over `source`, before the tree is built.
#[inline]
fn with_events<R>(source: &str, f: impl FnOnce(&Input<'_>, Vec<Event>) -> R) -> R {
    let grammar = Grammar {
        eof: K::Eof.raw(),
        error: K::Error.raw(),
        trivia: K::set(&[K::Whitespace]),
        max_depth: MAX_DEPTH,
    };
    let input = Input::new(source, lex(source), grammar);
    let mut p = Parser::new(&input);
    let root = p.start();
    query(&mut p);
    root.complete(&mut p, K::SourceFile.raw());
    let events = p.finish();
    f(&input, events)
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

fn at(p: &mut Parser<'_>, kind: K) -> bool {
    p.at(kind.raw())
}

/// The markers a clause opened before its body: a `FieldQuery` and a
/// `ModifiedClause`, completed inside out once the body is read.
struct Wrap {
    field: Option<Marker>,
    modified: Option<Marker>,
}

impl Wrap {
    fn finish(self, p: &mut Parser<'_>) {
        if let Some(m) = self.field {
            m.complete(p, K::FieldQuery.raw());
        }
        if let Some(m) = self.modified {
            m.complete(p, K::ModifiedClause.raw());
        }
    }
}

/// A clause list being read: the whole query, or the inside of a group
/// (`group` is that group's marker and what its clause opened around it).
struct List {
    m: Marker,
    clauses: usize,
    /// Whether an operator was read and a clause must follow.
    pending: bool,
    group: Option<(Marker, Wrap)>,
}

/// `_query`: clauses and operators up to the end. A group's clause list is
/// read by the same loop, on an explicit stack, not by recursion: a level
/// of nesting costs a `List` on the heap, not a chain of stack frames (five
/// rules deep, which held only about 640 levels on a 1 MB debug stack).
fn query(p: &mut Parser<'_>) {
    let mut stack = vec![List {
        m: p.start(),
        clauses: 0,
        pending: false,
        group: None,
    }];
    while let Some(list) = stack.last_mut() {
        let in_group = list.group.is_some();
        if p.at_eof() || (in_group && at(p, K::RParen)) {
            let Some(list) = stack.pop() else { break };
            end_list(p, list.m, list.clauses, list.pending);
            let Some((group, wrap)) = list.group else {
                break;
            };
            close_group(p, group);
            wrap.finish(p);
            if let Some(outer) = stack.last_mut() {
                outer.clauses += 1;
                outer.pending = false;
            }
            continue;
        }
        if list.clauses > 0 && !list.pending && (p.at_set(AND) || p.at_set(OR)) {
            conjunction(p);
            list.pending = true;
        } else if p.at_set(MODIFIERS) || p.at_set(BODIES) {
            match clause(p) {
                // The body is a group: read its clauses, then come back.
                Some(group) => stack.push(List {
                    m: p.start(),
                    clauses: 0,
                    pending: false,
                    group: Some(group),
                }),
                None => {
                    list.clauses += 1;
                    list.pending = false;
                }
            }
        } else {
            // A stray closer, an operator with no clause before it, `AND` where
            // a clause begins: the token is the error.
            if list.pending {
                p.error(MISSING_CLAUSE);
                list.pending = false;
            }
            p.err_and_bump(UNEXPECTED);
        }
    }
}

/// A clause list ends: one `BooleanQuery` when it holds more than one clause.
fn end_list(p: &mut Parser<'_>, m: Marker, clauses: usize, pending: bool) {
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

/// A clause with its modifier, if any. When its body is a group, the group
/// is open (its `(` read) and returned with what the clause opened around it.
fn clause(p: &mut Parser<'_>) -> Option<(Marker, Wrap)> {
    if !p.at_set(MODIFIERS) {
        return clause_body(p, None);
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
        clause_body(p, Some(m))
    } else {
        p.error(MISSING_CLAUSE);
        m.complete(p, K::ModifiedClause.raw());
        None
    }
}

/// `_clause`: a field query or a clause body.
fn clause_body(p: &mut Parser<'_>, modified: Option<Marker>) -> Option<(Marker, Wrap)> {
    if p.at_set(FIELD_NAMES) && p.nth(1) == K::Colon.raw() {
        let m = p.start();
        let name = p.start();
        term(p);
        name.complete(p, K::FieldName.raw());
        p.bump();
        let wrap = Wrap {
            field: Some(m),
            modified,
        };
        if p.at_set(BODIES) {
            body(p, wrap)
        } else {
            p.error(MISSING_CLAUSE);
            wrap.finish(p);
            None
        }
    } else {
        body(
            p,
            Wrap {
                field: None,
                modified,
            },
        )
    }
}

/// A group, a term, a phrase, a range or a regexp, with its suffixes. A
/// group is only opened here: `query` reads its clauses.
fn body(p: &mut Parser<'_>, wrap: Wrap) -> Option<(Marker, Wrap)> {
    let current = p.current();
    if current == K::LParen.raw() {
        if !p.enter() {
            wrap.finish(p);
            return None;
        }
        let m = p.start();
        p.bump();
        return Some((m, wrap));
    }
    if current == K::LBracket.raw() || current == K::LBrace.raw() {
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
    wrap.finish(p);
    None
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

/// A group's `)` and boost, after its clauses.
fn close_group(p: &mut Parser<'_>, m: Marker) {
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

    /// Queries of the corpus and the external sets, written here: an engine
    /// crate reads no file, its tests in `src/` included (`check-io-free.sh`).
    const SAMPLES: &[&str] = &[
        r#"(a OR b) AND c"#,
        r#"process.name:AND"#,
        r#"message:"failed login"#,
        r#"title:alert^2"#,
        r#"book.*:x"#,
        r#"bytes:[100 TO 200} AND @timestamp:[now-1d/d TO now]"#,
        r#"process.name:"#,
        r#"title:alert^"#,
        r#"name:jon~1 AND name:bob~AUTO"#,
        r#"process.name:cmd* AND file.name:a?c"#,
        r#"bytes:[100 TO]"#,
        r#"process.name:cmd.exe AND _exists_:host.name"#,
        r#"*:"#,
        r#"process.name:/cmd\.exe/"#,
        r#"+title:quick -body:"brown fox"~3 NOT status:500"#,
        r#"a && b || !c"#,
        r#"field:(one two "three four")^1.5"#,
        r#"port:>=1024 AND port:<49152"#,
        r#"path:C\:\\Windows\\System32\\*"#,
        r#"user.name:"SYSTEM" OR user.name:LOCAL\ SERVICE"#,
        r#"(a:1 or b:2) and c:3"#,
        r#"event.code >= 4624"#,
        r#"title:{a TO *]"#,
        r#"/re[gx]+p/ AND x"#,
    ];

    /// The samples, each cut at every
    /// character: valid and broken queries alike.
    fn texts() -> Vec<String> {
        let mut out: Vec<String> = SAMPLES.iter().map(|s| (*s).to_owned()).collect();
        let cut: Vec<String> = out
            .iter()
            .filter(|t| t.len() < 400)
            .flat_map(|t| {
                t.char_indices()
                    .map(|(i, _)| t.get(..i).unwrap().to_owned())
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
            sources.push(format!("{}a{}", "(".repeat(depth), ")".repeat(depth)));
        }
        let (mut accepted, mut rejected) = (0, 0);
        for source in &sources {
            let expected = parse(source).1.errors.is_empty();
            assert_eq!(accepts(source), expected, "{source:?}");
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
        assert!(!crate::parses("a AND (b OR c"));
        assert_eq!(trees_built() - before, 0);
        assert!(crate::parses("a AND (b OR c)"));
        assert_eq!(trees_built() - before, 1);
    }

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
            // The most nodes a level opens: a group, its clause list, a
            // modified clause and a field query.
            format!("{}b{}", "+a:(".repeat(levels), " c)".repeat(levels)),
        ] {
            let (_, parse) = parse(&source);
            assert!(parse.errors.is_empty(), "{:?}", &parse.errors[..1]);
        }
    }

    /// `f` on a 1 MB stack, as the browser WASM module has; the debug build
    /// spends the most stack per level.
    fn on_small_stack(name: &str, f: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .name(name.into())
            .stack_size(1 << 20)
            .spawn(f)
            .expect("a thread")
            .join()
            .unwrap_or_else(|_| panic!("{name} overflowed or panicked"));
    }

    #[test]
    fn nesting_at_and_past_the_limit_fits_a_small_stack() {
        let levels = usize::try_from(MAX_DEPTH).expect("fits");
        for (name, source, clean) in [
            (
                "balanced",
                format!("{}a{}", "(".repeat(levels), ")".repeat(levels)),
                true,
            ),
            (
                "field groups",
                format!("{}b{}", "a:(".repeat(levels), ")".repeat(levels)),
                true,
            ),
            (
                "modified groups",
                format!("{}b{}", "+a:(".repeat(levels), ")".repeat(levels)),
                true,
            ),
            (
                "modified groups of two clauses",
                format!("{}b{}", "+a:(".repeat(levels), " c)".repeat(levels)),
                true,
            ),
            ("unclosed", "(".repeat(levels), false),
            (
                "past the limit",
                format!("{}a{}", "(".repeat(200_000), ")".repeat(200_000)),
                false,
            ),
        ] {
            on_small_stack(name, move || {
                let (root, parse) = parse(&source);
                assert_eq!(parse.errors.is_empty(), clean, "{:?}", parse.errors.first());
                // The tree drops recursively too, and the debug rendering walks it.
                assert!(debug(&source).starts_with("SourceFile@"));
                drop(root);
            });
        }
    }

    #[test]
    fn a_stray_token_is_an_error_and_the_parse_goes_on() {
        let (root, parse) = parse("a ) b AND");
        assert_eq!(root.text(), "a ) b AND");
        assert!(parse.errors.len() >= 2);
    }
}
