//! The toolkit through its public API, on a toy language: `( … )` groups of
//! words, lexed with logos.

#![expect(
    clippy::string_slice,
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use logos::Logos;
use opentide_parse::{
    ErrorKind, Event, Grammar, Input, Lexeme, MAX_TREE_DEPTH, Parser, SyntaxError, TREE_BUDGET,
    TokenSet, build, debug_errors, debug_tree, lex,
};
use rowan::{SyntaxKind, TextRange, TextSize};
use std::thread;

#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    #[regex(r"[ \t\r\n]+")]
    Ws,
    #[regex(r"[a-z]+")]
    Word,
    #[token("(")]
    L,
    #[token(")")]
    R,
}

const WS: SyntaxKind = SyntaxKind(0);
const WORD: SyntaxKind = SyntaxKind(1);
const L: SyntaxKind = SyntaxKind(2);
const R: SyntaxKind = SyntaxKind(3);
const JUNK: SyntaxKind = SyntaxKind(4);
const EOF: SyntaxKind = SyntaxKind(5);
const ERROR: SyntaxKind = SyntaxKind(6);
const ROOT: SyntaxKind = SyntaxKind(7);
const GROUP: SyntaxKind = SyntaxKind(8);
const PAIR: SyntaxKind = SyntaxKind(9);
const NAMES: [&str; 10] = [
    "WS", "WORD", "L", "R", "JUNK", "EOF", "ERROR", "ROOT", "GROUP", "PAIR",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Toy {}

impl rowan::Language for Toy {
    type Kind = SyntaxKind;
    fn kind_from_raw(raw: SyntaxKind) -> SyntaxKind {
        raw
    }
    fn kind_to_raw(kind: SyntaxKind) -> SyntaxKind {
        kind
    }
}

fn name(kind: SyntaxKind) -> &'static str {
    NAMES[usize::from(kind.0)]
}

fn toy_lex(source: &str) -> Vec<Lexeme> {
    lex::<Tok>(source, |token, _| match token {
        Ok(Tok::Ws) => WS,
        Ok(Tok::Word) => WORD,
        Ok(Tok::L) => L,
        Ok(Tok::R) => R,
        Err(()) => JUNK,
    })
}

fn grammar(max_depth: u32) -> Grammar {
    Grammar {
        eof: EOF,
        error: ERROR,
        trivia: TokenSet::new(&[WS]),
        max_depth,
    }
}

/// Parses `source`; checks the tree is lossless; returns it as text.
fn parse(source: &str, max_depth: u32) -> (String, Vec<SyntaxError>) {
    let input = Input::new(source, toy_lex(source), grammar(max_depth));
    let mut p = Parser::new(&input);
    let root = p.start();
    loop {
        items(&mut p);
        if p.at_eof() {
            break;
        }
        p.err_and_bump("unexpected");
    }
    root.complete(&mut p, ROOT);
    let parse = build(&input, p.finish());
    let node = rowan::SyntaxNode::<Toy>::new_root(parse.green);
    assert_eq!(node.to_string(), source, "lossless");
    (debug_tree(&node, name), parse.errors)
}

fn items(p: &mut Parser<'_>) {
    loop {
        if p.at(WORD) {
            p.bump();
        } else if p.at(L) {
            if !p.enter() {
                return;
            }
            let m = p.start();
            p.bump();
            items(p);
            if !p.at(R) {
                p.err_recover("missing `)`", TokenSet::new(&[R]));
            }
            p.eat(R);
            m.complete(p, GROUP);
            p.exit();
        } else {
            return;
        }
    }
}

fn on_small_stack(run: impl FnOnce() + Send + 'static) {
    thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
}

fn at(start: u32, end: u32) -> TextRange {
    TextRange::new(TextSize::from(start), TextSize::from(end))
}

/// Errors on multi-byte characters restart the lexer on a char boundary:
/// every suffix of such a text lexes back to itself (#1946).
#[test]
fn every_suffix_of_multi_byte_text_lexes_losslessly() {
    let source = "é😀 a(é) 😀?é\n😀";
    for (at, _) in source.char_indices() {
        let rest = source.get(at..).unwrap();
        let text: String = toy_lex(rest)
            .iter()
            .map(|l| rest.get(std::ops::Range::<usize>::from(l.range)).unwrap())
            .collect();
        assert_eq!(text, rest);
    }
}

#[test]
fn the_lexer_is_lossless_and_an_error_is_one_character() {
    let source = "ab é😀(x)\n ?";
    let lexemes = toy_lex(source);
    let kinds: Vec<_> = lexemes
        .iter()
        .map(|l| {
            (
                name(l.kind),
                &source[std::ops::Range::<usize>::from(l.range)],
            )
        })
        .collect();
    assert_eq!(
        kinds,
        [
            ("WORD", "ab"),
            ("WS", " "),
            ("JUNK", "é"),
            ("JUNK", "😀"),
            ("L", "("),
            ("WORD", "x"),
            ("R", ")"),
            ("WS", "\n "),
            ("JUNK", "?"),
        ]
    );
    let mut end = TextSize::from(0);
    for l in &lexemes {
        assert_eq!(l.range.start(), end, "contiguous");
        end = l.range.end();
    }
    assert_eq!(end, TextSize::of(source));
}

#[test]
fn trivia_goes_to_the_parent_and_errors_carry_the_expected_set() {
    let (tree, errors) = parse(" a (b c ", 8);
    insta::assert_snapshot!(tree, @r#"
    ROOT@0..8
      WS@0..1 " "
      WORD@1..2 "a"
      WS@2..3 " "
      GROUP@3..7
        L@3..4 "("
        WORD@4..5 "b"
        WS@5..6 " "
        WORD@6..7 "c"
      WS@7..8 " "
    "#);
    assert_eq!(
        debug_errors(&errors, name),
        "7..8: missing `)` (expected WORD, L, R)\n"
    );
    assert_eq!(errors[0].gap, at(7, 8));
    assert_eq!(errors[0].kind, ErrorKind::Syntax);
}

#[test]
fn unexpected_tokens_are_error_nodes_and_parsing_goes_on() {
    let (tree, errors) = parse("a ) (b ?) c", 8);
    insta::assert_snapshot!(tree, @r#"
    ROOT@0..11
      WORD@0..1 "a"
      WS@1..2 " "
      ERROR@2..3
        R@2..3 ")"
      WS@3..4 " "
      GROUP@4..9
        L@4..5 "("
        WORD@5..6 "b"
        WS@6..7 " "
        ERROR@7..8
          JUNK@7..8 "?"
        R@8..9 ")"
      WS@9..10 " "
      WORD@10..11 "c"
    "#);
    assert_eq!(
        debug_errors(&errors, name),
        "1..2: unexpected (expected WORD, L)\n6..7: missing `)` (expected WORD, L, R)\n"
    );
}

#[test]
fn nesting_up_to_the_limit_parses_and_one_past_it_is_one_error() {
    let deep = |n: usize| format!("{}a{}", "(".repeat(n), ")".repeat(n));
    on_small_stack(move || {
        let (_, errors) = parse(&deep(64), 64);
        assert_eq!(errors, []);
        let (tree, errors) = parse(&deep(65), 64);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].kind, ErrorKind::TooDeep { limit: 64 });
        assert_eq!(errors[0].message, "nesting deeper than 64 levels");
        // The 65th `(` and everything after it is one error node.
        assert!(tree.contains("ERROR@64..131"), "{tree}");
    });
}

#[test]
fn a_hundred_thousand_open_parens_are_one_diagnostic_on_a_small_stack() {
    on_small_stack(|| {
        let (_, errors) = parse(&"(".repeat(100_000), 200);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].kind, ErrorKind::TooDeep { limit: 200 });
    });
}

/// `build` never recurses; rowan drops a green tree recursively, which on a
/// 1 MB stack holds about 10 000 levels in a debug build (measured on
/// aarch64 macOS: 8 000 drop, 12 000 overflow). `MAX_TREE_DEPTH` (4 096)
/// keeps under half of that; this checks a tree just below it.
#[test]
fn a_tree_four_thousand_nodes_deep_builds_and_drops_on_a_small_stack() {
    const N: usize = 4_000;
    on_small_stack(|| {
        let source = "(".repeat(N);
        let input = Input::new(&source, toy_lex(&source), grammar(u32::MAX));
        let mut p = Parser::new(&input);
        let open: Vec<_> = (0..N)
            .map(|_| {
                let m = p.start();
                p.bump();
                m
            })
            .collect();
        for m in open.into_iter().rev() {
            m.complete(&mut p, GROUP);
        }
        let parse = build(&input, p.finish());
        assert_eq!(parse.depth, N);
        let node = rowan::SyntaxNode::<Toy>::new_root(parse.green);
        assert_eq!(node.to_string(), source);
    });
}

#[test]
fn random_inputs_never_panic_hang_or_lose_a_byte() {
    // xorshift: deterministic, so a failure reproduces.
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let pieces = [
        "a", "bc", " ", "\n", "(", ")", "((", "))", "?", "é", "😀", "",
    ];
    for _ in 0..3_000 {
        let len = next() % 40;
        let source: String = (0..len)
            .map(|_| pieces[usize::try_from(next() % 12).unwrap()])
            .collect();
        let depth = u32::try_from(next() % 6).unwrap();
        let (_, errors) = parse(&source, depth);
        for e in &errors {
            assert!(e.gap.end() <= TextSize::of(source.as_str()), "{source:?}");
            assert!(source.is_char_boundary(usize::from(e.gap.start())));
        }
    }
}

/// Parses `source` with `grammar` driving the parser; returns the tree as
/// text and the parse.
fn parse_with(source: &str, grammar: impl FnOnce(&mut Parser<'_>)) -> (String, Vec<SyntaxError>) {
    let input = Input::new(source, toy_lex(source), self::grammar(8));
    let mut p = Parser::new(&input);
    grammar(&mut p);
    let parse = build(&input, p.finish());
    let node = rowan::SyntaxNode::<Toy>::new_root(parse.green);
    assert_eq!(node.to_string(), source, "lossless");
    (debug_tree(&node, name), parse.errors)
}

/// A Pratt loop that wraps `a` in a node, gives up (`abandon`), and parses
/// `b` as a sibling: the abandoned wrapper must not leave `a` pointing at
/// the next node opened, which would make `b`'s node enclose `a`'s.
#[test]
fn an_abandoned_wrapper_lets_go_of_the_node_it_preceded() {
    let (tree, errors) = parse_with("a b", |p| {
        let root = p.start();
        let a = p.start();
        p.bump();
        let a = a.complete(p, GROUP);
        a.precede(p).abandon(p);
        let b = p.start();
        p.bump();
        b.complete(p, PAIR);
        root.complete(p, ROOT);
    });
    assert_eq!(errors, []);
    insta::assert_snapshot!(tree, @r#"
    ROOT@0..3
      GROUP@0..1
        WORD@0..1 "a"
      WS@1..2 " "
      PAIR@2..3
        WORD@2..3 "b"
    "#);
}

/// After an abandoned wrapper, the node can be wrapped again.
#[test]
fn a_node_can_be_preceded_again_after_an_abandon() {
    let (tree, _) = parse_with("a b", |p| {
        let root = p.start();
        let a = p.start();
        p.bump();
        let a = a.complete(p, GROUP);
        a.precede(p).abandon(p);
        let pair = a.precede(p);
        p.bump();
        pair.complete(p, PAIR);
        root.complete(p, ROOT);
    });
    insta::assert_snapshot!(tree, @r#"
    ROOT@0..3
      PAIR@0..3
        GROUP@0..1
          WORD@0..1 "a"
        WS@1..2 " "
        WORD@2..3 "b"
    "#);
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "preceded twice")]
fn preceding_a_node_twice_panics_in_debug_builds() {
    let _ = parse_with("a", |p| {
        let root = p.start();
        let a = p.start();
        p.bump();
        let a = a.complete(p, GROUP);
        let outer = a.precede(p);
        let inner = a.precede(p);
        inner.complete(p, PAIR);
        outer.complete(p, PAIR);
        root.complete(p, ROOT);
    });
}

/// A left-associative loop (`a b c …` as `((a b) c) …`, one `precede` per
/// word) nests the tree without calling `enter`. 30 000 levels overflow a
/// 1 MB stack when rowan drops the tree; `precede` stops the parse at
/// `TREE_BUDGET` nodes instead, with one `TooDeep` naming that limit and no
/// byte lost (#1427).
#[test]
fn a_long_left_associative_chain_ends_in_one_too_deep() {
    const N: usize = 30_000;
    on_small_stack(|| {
        let source = "a ".repeat(N);
        let input = Input::new(&source, toy_lex(&source), grammar(8));
        let mut p = Parser::new(&input);
        let root = p.start();
        let first = p.start();
        p.bump();
        let mut lhs = first.complete(&mut p, PAIR);
        while p.at(WORD) {
            let m = lhs.precede(&mut p);
            p.bump();
            lhs = m.complete(&mut p, PAIR);
        }
        root.complete(&mut p, ROOT);
        let parse = build(&input, p.finish());
        assert!(parse.depth <= MAX_TREE_DEPTH, "{}", parse.depth);
        assert_eq!(parse.errors.len(), 1, "{:?}", parse.errors);
        let limit = u32::try_from(TREE_BUDGET).unwrap();
        assert_eq!(parse.errors[0].kind, ErrorKind::TooDeep { limit });
        assert_eq!(
            parse.errors[0].message,
            format!("nesting deeper than the syntax tree allows ({limit} nodes)")
        );
        let node = rowan::SyntaxNode::<Toy>::new_root(parse.green);
        assert_eq!(node.to_string(), source, "lossless");
    });
}

/// `build` keeps its own bound for events no `Parser` checked: past
/// `MAX_TREE_DEPTH` it flattens, with one `TreeTooDeep`, no byte lost.
#[test]
fn build_flattens_events_past_the_tree_limit() {
    const N: usize = 30_000;
    on_small_stack(|| {
        let source = "a ".repeat(N);
        let input = Input::new(&source, toy_lex(&source), grammar(8));
        let mut events = Vec::new();
        events.push(Event::Start {
            kind: ROOT,
            forward_parent: None,
        });
        for _ in 0..N {
            events.push(Event::Start {
                kind: PAIR,
                forward_parent: None,
            });
            events.push(Event::Token { kind: WORD });
        }
        events.extend(std::iter::repeat_n(Event::Finish, N + 1));
        let parse = build(&input, events);
        assert_eq!(parse.depth, MAX_TREE_DEPTH);
        assert_eq!(parse.errors.len(), 1, "{:?}", parse.errors);
        let limit = u32::try_from(MAX_TREE_DEPTH).unwrap();
        assert_eq!(parse.errors[0].kind, ErrorKind::TreeTooDeep { limit });
        let node = rowan::SyntaxNode::<Toy>::new_root(parse.green);
        assert_eq!(node.to_string(), source, "lossless");
    });
}

/// Found by review (#1473): a wrap of a node with a tall sibling after it
/// counted the node alone, and wraps after the budget was spent still nested.
/// Both end in one `TooDeep` within `MAX_TREE_DEPTH`, never `TreeTooDeep`.
#[test]
fn wraps_count_later_siblings_and_stop_at_the_budget() {
    on_small_stack(|| {
        let source = format!("a {}", "( ".repeat(5_000));
        let input = Input::new(&source, toy_lex(&source), grammar(u32::MAX));
        let mut p = Parser::new(&input);
        let root = p.start();
        let first = p.start();
        p.bump();
        let mut c = first.complete(&mut p, PAIR);
        // A sibling 4,000 nodes tall, completed after `c`.
        let tall: Vec<_> = (0..4_000).map(|_| p.start()).collect();
        p.bump();
        for m in tall.into_iter().rev() {
            m.complete(&mut p, GROUP);
        }
        // Wraps of `c`, each with a token, then wraps with none left.
        for _ in 0..6_000 {
            let m = c.precede(&mut p);
            if p.at(L) {
                p.bump();
            }
            c = m.complete(&mut p, PAIR);
        }
        root.complete(&mut p, ROOT);
        let parse = build(&input, p.finish());
        assert!(parse.depth <= MAX_TREE_DEPTH, "{}", parse.depth);
        let kinds: Vec<_> = parse.errors.iter().map(|e| e.kind).collect();
        let limit = u32::try_from(TREE_BUDGET).unwrap();
        assert_eq!(kinds, [ErrorKind::TooDeep { limit }]);
        let node = rowan::SyntaxNode::<Toy>::new_root(parse.green);
        assert_eq!(node.to_string(), source, "lossless");
    });
}

/// A level that opens many nodes is charged them: nested groups of eight
/// nodes a level end in one `TooDeep` naming the node limit, well before
/// `max_depth` levels, and the tree stays under `MAX_TREE_DEPTH` (#1427).
#[test]
fn levels_that_open_many_nodes_end_in_one_too_deep() {
    fn group(p: &mut Parser<'_>) {
        if !p.enter() {
            return;
        }
        let outer: Vec<_> = (0..7).map(|_| p.start()).collect();
        let m = p.start();
        p.bump();
        if p.at(L) {
            group(p);
        }
        if p.at(R) {
            p.bump();
        }
        m.complete(p, GROUP);
        for o in outer.into_iter().rev() {
            o.complete(p, PAIR);
        }
        p.exit();
    }
    on_small_stack(|| {
        let n = 1_000;
        let source = format!("{}{}", "(".repeat(n), ")".repeat(n));
        let input = Input::new(&source, toy_lex(&source), grammar(10_000));
        let mut p = Parser::new(&input);
        let root = p.start();
        group(&mut p);
        root.complete(&mut p, ROOT);
        let parse = build(&input, p.finish());
        assert!(parse.depth <= MAX_TREE_DEPTH, "{}", parse.depth);
        let kinds: Vec<_> = parse.errors.iter().map(|e| e.kind).collect();
        let limit = u32::try_from(TREE_BUDGET).unwrap();
        assert_eq!(kinds, [ErrorKind::TooDeep { limit }]);
        let node = rowan::SyntaxNode::<Toy>::new_root(parse.green);
        assert_eq!(node.to_string(), source, "lossless");
    });
}

/// `nth_range` and `source` let a grammar see layout the kinds do not
/// carry: whether two tokens touch, and the bytes between them.
#[test]
fn a_grammar_reads_token_ranges_ahead_and_the_source() {
    let source = "a (b) c";
    let input = Input::new(source, toy_lex(source), grammar(8));
    let mut p = Parser::new(&input);
    assert_eq!(p.nth_range(0), Some(at(0, 1)));
    assert_eq!(p.nth_range(1), Some(at(2, 3)), "trivia is skipped");
    assert_eq!(p.nth_range(2), Some(at(3, 4)));
    assert_eq!(p.nth_range(5), None, "past the last token");
    assert_eq!(p.current_range(), p.nth_range(0));
    // `(` and `b` touch; `a` and `(` do not.
    let touch = |p: &Parser<'_>, n: usize| {
        p.nth_range(n)
            .zip(p.nth_range(n + 1))
            .is_some_and(|(x, y)| x.end() == y.start())
    };
    assert!(!touch(&p, 0));
    assert!(touch(&p, 1));
    let between = p
        .nth_range(0)
        .zip(p.nth_range(1))
        .map(|(x, y)| &p.source()[usize::from(x.end())..usize::from(y.start())]);
    assert_eq!(between, Some(" "));
    let root = p.start();
    while !p.at_eof() {
        p.bump();
    }
    root.complete(&mut p, ROOT);
    assert_eq!(p.nth_range(0), None, "at end of input");
    let _ = build(&input, p.finish());
}

#[test]
fn nth_range_is_none_once_the_parser_has_stalled() {
    let source = "a b";
    let input = Input::new(source, toy_lex(source), grammar(8));
    let mut p = Parser::with_fuel(&input, 3);
    for _ in 0..10 {
        let _ = p.at(WORD);
    }
    assert!(p.stalled());
    assert_eq!(p.nth_range(0), None);
    assert_eq!(p.nth_range(1), None);
}

/// `nth_range` burns fuel like `nth`: a loop that only reads ranges stalls.
#[test]
fn a_loop_that_only_reads_ranges_stalls() {
    let source = "a b";
    let input = Input::new(source, toy_lex(source), grammar(8));
    let p = Parser::with_fuel(&input, 50);
    let mut reads = 0;
    while p.nth_range(0).is_some() {
        reads += 1;
        assert!(reads < 1_000, "nth_range never ran out of fuel");
    }
    assert!(p.stalled());
}

/// `SyntaxError::within` is the nodes open when the grammar recorded the error, in the
/// order of its events: an error recorded inside a node is in it, one recorded after the
/// node closed is not, though both sit at the node's end.
#[test]
fn an_error_records_the_nodes_it_was_recorded_in() {
    let source = "a b";
    let input = Input::new(source, toy_lex(source), grammar(8));
    let mut p = Parser::new(&input);
    let root = p.start();
    let group = p.start();
    p.bump();
    p.error("inside");
    group.complete(&mut p, GROUP);
    p.error("after");
    p.bump();
    root.complete(&mut p, ROOT);
    let parse = build(&input, p.finish());
    let within: Vec<_> = parse.errors.iter().map(|e| e.within.clone()).collect();
    assert_eq!(within, [vec![ROOT, GROUP], vec![ROOT]]);
    assert_eq!(parse.errors[0].gap, parse.errors[1].gap, "the same gap");
}
