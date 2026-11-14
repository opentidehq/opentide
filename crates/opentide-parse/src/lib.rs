//! The parsing toolkit of opentide's pure-Rust parsers, on the rust-analyzer
//! pattern: a [logos] lexer feeds a token [`Input`] (trivia kept for the
//! tree, skipped for lookahead); hand-written grammar functions drive a
//! [`Parser`] that records [`Event`]s through [`Marker`]s; [`build`] turns the
//! events into a lossless [`rowan`] green tree and a list of [`SyntaxError`]s.
//!
//! The toolkit knows no language: kinds are [`rowan::SyntaxKind`] (a `u16`),
//! and a language names the few it needs in a [`Grammar`].
//!
//! ```
//! use opentide_parse::{Grammar, Input, Lexeme, Parser, TokenSet, build, debug_tree};
//! use rowan::{SyntaxKind, TextRange, TextSize};
//!
//! // A toy language: `WORD (PLUS WORD)*`.
//! const WS: SyntaxKind = SyntaxKind(0);
//! const WORD: SyntaxKind = SyntaxKind(1);
//! const PLUS: SyntaxKind = SyntaxKind(2);
//! const EOF: SyntaxKind = SyntaxKind(3);
//! const ERROR: SyntaxKind = SyntaxKind(4);
//! const ROOT: SyntaxKind = SyntaxKind(5);
//! const SUM: SyntaxKind = SyntaxKind(6);
//! let grammar = Grammar { eof: EOF, error: ERROR, trivia: TokenSet::new(&[WS]), max_depth: 64 };
//!
//! let source = "a + b";
//! let at = |s: u32, e: u32| TextRange::new(TextSize::from(s), TextSize::from(e));
//! let lexemes = vec![
//!     Lexeme { kind: WORD, range: at(0, 1) },
//!     Lexeme { kind: WS, range: at(1, 2) },
//!     Lexeme { kind: PLUS, range: at(2, 3) },
//!     Lexeme { kind: WS, range: at(3, 4) },
//!     Lexeme { kind: WORD, range: at(4, 5) },
//! ];
//! let input = Input::new(lexemes, grammar);
//! let mut p = Parser::new(&input);
//! let root = p.start();
//! let lhs = p.start();
//! p.expect(WORD, "missing");
//! let lhs = lhs.complete(&mut p, SUM);
//! let sum = lhs.precede(&mut p);
//! while p.eat(PLUS) {
//!     p.expect(WORD, "missing");
//! }
//! sum.complete(&mut p, SUM);
//! root.complete(&mut p, ROOT);
//! let parse = build(source, &input, p.finish());
//! assert!(parse.errors.is_empty());
//! assert_eq!(parse.green.to_string(), source);
//! ```

use rowan::{GreenNode, GreenNodeBuilder, SyntaxKind, TextRange, TextSize};
use std::fmt::Write as _;

pub use logos;
pub use rowan;

/// A set of token kinds below 128, as a bitset: what the parser looked for
/// at a failure.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokenSet(u128);

impl TokenSet {
    /// No kind.
    pub const EMPTY: Self = Self(0);

    /// The set of `kinds`; a kind of 128 or more is left out.
    pub const fn new(kinds: &[SyntaxKind]) -> Self {
        let mut bits = 0u128;
        let mut i = 0;
        while i < kinds.len() {
            if kinds[i].0 < 128 {
                bits |= 1 << kinds[i].0;
            }
            i += 1;
        }
        Self(bits)
    }

    /// Both sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether `kind` is in the set.
    pub const fn contains(self, kind: SyntaxKind) -> bool {
        kind.0 < 128 && self.0 & (1 << kind.0) != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The kinds in the set, smallest first.
    pub fn iter(self) -> impl Iterator<Item = SyntaxKind> {
        (0..128u16)
            .filter(move |k| self.0 & (1 << k) != 0)
            .map(SyntaxKind)
    }
}

/// The kinds a language gives the toolkit.
#[derive(Clone, Copy, Debug)]
pub struct Grammar {
    /// What [`Parser::current`] returns past the last token.
    pub eof: SyntaxKind,
    /// The node that wraps unexpected tokens.
    pub error: SyntaxKind,
    /// Whitespace and comments: in the tree, never seen by the grammar.
    pub trivia: TokenSet,
    /// The deepest nesting [`Parser::enter`] allows; past it the rest of the
    /// input is one error node and one diagnostic, never a stack overflow.
    pub max_depth: u32,
}

/// One token of the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lexeme {
    /// Its kind.
    pub kind: SyntaxKind,
    /// Where it is.
    pub range: TextRange,
}

/// Lexes `source` with the logos token `T`; `kind` maps each token (or
/// logos's error) and its text to a kind. Every byte ends up in one lexeme.
/// An error is one character, and lexing resumes after it (as tree-sitter's
/// lexer skips a character): logos does not backtrack, so its error span
/// would swallow a valid prefix of what follows (`\u12` after a bad `\`).
pub fn lex<'s, T>(
    source: &'s str,
    mut kind: impl FnMut(Result<T, T::Error>, &'s str) -> SyntaxKind,
) -> Vec<Lexeme>
where
    T: logos::Logos<'s, Source = str>,
    T::Extras: Default,
{
    let mut out = Vec::new();
    let mut base = 0;
    'restart: while base < source.len() {
        let mut lexer = T::lexer(&source[base..]);
        while let Some(token) = lexer.next() {
            let span = lexer.span();
            let (start, mut end) = (base + span.start, base + span.end);
            let error = token.is_err();
            if error {
                end = start + source[start..].chars().next().map_or(1, char::len_utf8);
            }
            out.push(Lexeme {
                kind: kind(token, &source[start..end]),
                range: range(start, end),
            });
            if error {
                base = end;
                continue 'restart;
            }
        }
        break;
    }
    out
}

fn range(start: usize, end: usize) -> TextRange {
    let at = |n: usize| TextSize::from(u32::try_from(n).unwrap_or(u32::MAX));
    TextRange::new(at(start), at(end.max(start)))
}

/// The lexemes of a source, with the significant ones (not trivia) indexed
/// for the parser's lookahead.
#[derive(Debug)]
pub struct Input {
    lexemes: Vec<Lexeme>,
    significant: Vec<usize>,
    grammar: Grammar,
}

impl Input {
    /// The input of `lexemes`, in source order.
    pub fn new(lexemes: Vec<Lexeme>, grammar: Grammar) -> Self {
        let significant = (0..lexemes.len())
            .filter(|&i| !grammar.trivia.contains(lexemes[i].kind))
            .collect();
        Self {
            lexemes,
            significant,
            grammar,
        }
    }

    /// Every lexeme, trivia included.
    pub fn lexemes(&self) -> &[Lexeme] {
        &self.lexemes
    }

    fn kind(&self, n: usize) -> SyntaxKind {
        self.significant
            .get(n)
            .map_or(self.grammar.eof, |&i| self.lexemes[i].kind)
    }

    fn range(&self, n: usize) -> Option<TextRange> {
        self.significant.get(n).map(|&i| self.lexemes[i].range)
    }
}

/// What a grammar function records; [`build`] replays them into a tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A node starts. `forward_parent` is the distance to the event of a
    /// node that [`CompletedMarker::precede`] opened around this one.
    Start {
        /// The node's kind.
        kind: SyntaxKind,
        /// The node that encloses this one, opened later.
        forward_parent: Option<u32>,
    },
    /// The next significant token, as `kind` (a grammar may reclassify it).
    Token {
        /// The kind it takes in the tree.
        kind: SyntaxKind,
    },
    /// The innermost open node ends.
    Finish,
    /// A syntax error before the next token.
    Error {
        /// The grammar's message.
        message: String,
        /// The kinds the parser looked for there.
        expected: TokenSet,
    },
    /// A marker never completed, or one moved by `precede`.
    Tombstone,
}

/// A syntax error of a parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    /// The grammar's message.
    pub message: String,
    /// The kinds the parser looked for.
    pub expected: TokenSet,
    /// From the end of the last token before the error to the start of the
    /// token after it: the error sits in this gap (its trivia).
    pub gap: TextRange,
}

/// A grammar's cursor over an [`Input`]: lookahead, consumption, markers,
/// errors with the expected set, and the nesting guard.
#[derive(Debug)]
pub struct Parser<'i> {
    input: &'i Input,
    pos: usize,
    events: Vec<Event>,
    expected: TokenSet,
    fuel: std::cell::Cell<u32>,
    depth: u32,
    poisoned: bool,
}

/// Lookups without progress before the parser reads end of input: a grammar
/// loop that never consumes ends instead of hanging.
const FUEL: u32 = 1 << 16;

impl<'i> Parser<'i> {
    /// A parser at the start of `input`.
    pub fn new(input: &'i Input) -> Self {
        Self {
            input,
            pos: 0,
            events: Vec::new(),
            expected: TokenSet::EMPTY,
            fuel: std::cell::Cell::new(FUEL),
            depth: 0,
            poisoned: false,
        }
    }

    /// The kind of the `n`th significant token ahead.
    pub fn nth(&self, n: usize) -> SyntaxKind {
        let fuel = self.fuel.get();
        if fuel == 0 {
            return self.input.grammar.eof;
        }
        self.fuel.set(fuel - 1);
        self.input.kind(self.pos + n)
    }

    /// The kind of the current token.
    pub fn current(&self) -> SyntaxKind {
        self.nth(0)
    }

    /// Where the current token is; `None` at end of input.
    pub fn current_range(&self) -> Option<TextRange> {
        self.input.range(self.pos)
    }

    /// Whether the current token is `kind`; a miss adds `kind` to the
    /// expected set of the next error.
    pub fn at(&mut self, kind: SyntaxKind) -> bool {
        self.expected = self.expected.union(TokenSet::new(&[kind]));
        self.current() == kind
    }

    /// Whether the current token is in `set` (recorded as [`Parser::at`]).
    pub fn at_set(&mut self, set: TokenSet) -> bool {
        self.expected = self.expected.union(set);
        set.contains(self.current())
    }

    /// Whether the input is consumed.
    pub fn at_eof(&self) -> bool {
        self.current() == self.input.grammar.eof
    }

    /// Consumes the current token as it was lexed.
    pub fn bump(&mut self) {
        let kind = self.current();
        self.bump_as(kind);
    }

    /// Consumes the current token as `kind` (a keyword read as a word).
    pub fn bump_as(&mut self, kind: SyntaxKind) {
        if self.pos >= self.input.significant.len() {
            return;
        }
        self.events.push(Event::Token { kind });
        self.pos += 1;
        self.expected = TokenSet::EMPTY;
        self.fuel.set(FUEL);
    }

    /// Consumes the current token if it is `kind`.
    pub fn eat(&mut self, kind: SyntaxKind) -> bool {
        let found = self.at(kind);
        if found {
            self.bump();
        }
        found
    }

    /// Consumes `kind`, or records `message` without consuming.
    pub fn expect(&mut self, kind: SyntaxKind, message: &str) -> bool {
        let found = self.eat(kind);
        if !found {
            self.error(message);
        }
        found
    }

    /// Records an error before the current token, with the expected set.
    /// After [`Parser::enter`] refused, errors are dropped: one is enough.
    pub fn error(&mut self, message: &str) {
        if self.poisoned {
            return;
        }
        self.events.push(Event::Error {
            message: message.to_string(),
            expected: self.expected,
        });
    }

    /// Records an error and wraps the current token in an error node.
    pub fn err_and_bump(&mut self, message: &str) {
        let m = self.start();
        self.error(message);
        self.bump();
        m.complete(self, self.input.grammar.error);
    }

    /// Records an error and wraps tokens up to one in `stop` (or the end)
    /// in an error node.
    pub fn err_until(&mut self, message: &str, stop: TokenSet) {
        let m = self.start();
        self.error(message);
        while !self.at_eof() && !stop.contains(self.current()) {
            self.bump();
        }
        m.complete(self, self.input.grammar.error);
    }

    /// Opens a node.
    pub fn start(&mut self) -> Marker {
        let pos = u32::try_from(self.events.len()).unwrap_or(u32::MAX);
        self.events.push(Event::Tombstone);
        Marker { pos }
    }

    /// One level deeper. Past `max_depth` it records one error, wraps the
    /// rest of the input in an error node, and returns `false`: the caller
    /// returns at once, and so does everything above it, the input consumed.
    pub fn enter(&mut self) -> bool {
        self.depth += 1;
        if self.depth <= self.input.grammar.max_depth {
            return true;
        }
        let limit = self.input.grammar.max_depth;
        self.err_until(
            &format!("nesting deeper than {limit} levels"),
            TokenSet::EMPTY,
        );
        self.poisoned = true;
        false
    }

    /// One level up, after [`Parser::enter`].
    pub fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// The events, for [`build`].
    pub fn finish(self) -> Vec<Event> {
        self.events
    }
}

/// An open node: [`Marker::complete`] closes it, [`Marker::abandon`] drops it.
#[derive(Debug)]
pub struct Marker {
    pos: u32,
}

impl Marker {
    /// Closes the node as `kind`.
    pub fn complete(self, p: &mut Parser<'_>, kind: SyntaxKind) -> CompletedMarker {
        if let Some(event) = p.events.get_mut(self.pos as usize) {
            *event = Event::Start {
                kind,
                forward_parent: None,
            };
        }
        p.events.push(Event::Finish);
        CompletedMarker {
            pos: self.pos,
            kind,
        }
    }

    /// Drops the node; its tokens belong to the enclosing one.
    pub fn abandon(self, p: &mut Parser<'_>) {
        if self.pos as usize + 1 == p.events.len() {
            p.events.pop();
        }
    }
}

/// A closed node, which [`CompletedMarker::precede`] can wrap in a new one.
#[derive(Clone, Copy, Debug)]
pub struct CompletedMarker {
    pos: u32,
    kind: SyntaxKind,
}

impl CompletedMarker {
    /// Opens a node that starts where this one does and encloses it
    /// (`a + b` after `a` is parsed).
    pub fn precede(self, p: &mut Parser<'_>) -> Marker {
        let m = p.start();
        if let Some(Event::Start { forward_parent, .. }) = p.events.get_mut(self.pos as usize) {
            *forward_parent = Some(m.pos - self.pos);
        }
        m
    }

    /// The node's kind.
    pub fn kind(self) -> SyntaxKind {
        self.kind
    }
}

/// A green tree and its syntax errors.
#[derive(Clone, Debug)]
pub struct Parse {
    /// The lossless tree: every byte of the source, trivia included.
    pub green: GreenNode,
    /// The errors, in source order.
    pub errors: Vec<SyntaxError>,
}

/// Replays `events` over `input` into a green tree. Trivia before a node
/// goes to its parent, so a node's range starts and ends at a significant
/// token; trivia between a node's tokens stays inside it.
pub fn build(source: &str, input: &Input, mut events: Vec<Event>) -> Parse {
    let mut builder = GreenNodeBuilder::new();
    let mut errors = Vec::new();
    let lexemes = &input.lexemes;
    let mut next = 0usize; // next lexeme to emit
    let mut depth = 0usize;
    let mut last_end = TextSize::from(0);
    let text = |l: &Lexeme| {
        source
            .get(std::ops::Range::<usize>::from(l.range))
            .unwrap_or("")
    };
    let mut parents = Vec::new();
    for i in 0..events.len() {
        match std::mem::replace(&mut events[i], Event::Tombstone) {
            Event::Start {
                kind,
                forward_parent,
            } => {
                parents.clear();
                parents.push(kind);
                let (mut at, mut fp) = (i, forward_parent);
                while let Some(distance) = fp {
                    at += distance as usize;
                    fp = match std::mem::replace(&mut events[at], Event::Tombstone) {
                        Event::Start {
                            kind,
                            forward_parent,
                        } => {
                            parents.push(kind);
                            forward_parent
                        }
                        _ => None,
                    };
                }
                for &kind in parents.iter().rev() {
                    if depth > 0 {
                        flush_trivia(&mut builder, input, &mut next, &text);
                    }
                    builder.start_node(kind);
                    depth += 1;
                }
            }
            Event::Finish => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    flush_rest(&mut builder, input, &mut next, &text);
                }
                builder.finish_node();
            }
            Event::Token { kind } => {
                flush_trivia(&mut builder, input, &mut next, &text);
                if let Some(l) = lexemes.get(next) {
                    builder.token(kind, text(l));
                    last_end = l.range.end();
                    next += 1;
                }
            }
            Event::Error { message, expected } => {
                let after = lexemes[next..]
                    .iter()
                    .find(|l| !input.grammar.trivia.contains(l.kind))
                    .map_or(TextSize::of(source), |l| l.range.start());
                errors.push(SyntaxError {
                    message,
                    expected,
                    gap: TextRange::new(last_end, after.max(last_end)),
                });
            }
            Event::Tombstone => {}
        }
    }
    Parse {
        green: builder.finish(),
        errors,
    }
}

fn flush_trivia<'s>(
    builder: &mut GreenNodeBuilder<'_>,
    input: &Input,
    next: &mut usize,
    text: &impl Fn(&Lexeme) -> &'s str,
) {
    while let Some(l) = input.lexemes.get(*next) {
        if !input.grammar.trivia.contains(l.kind) {
            break;
        }
        builder.token(l.kind, text(l));
        *next += 1;
    }
}

/// What is left when the root closes: trivia, and tokens a grammar left
/// unconsumed (in an error node, so the tree stays lossless).
fn flush_rest<'s>(
    builder: &mut GreenNodeBuilder<'_>,
    input: &Input,
    next: &mut usize,
    text: &impl Fn(&Lexeme) -> &'s str,
) {
    flush_trivia(builder, input, next, text);
    if *next < input.lexemes.len() {
        builder.start_node(input.grammar.error);
        for l in &input.lexemes[*next..] {
            builder.token(l.kind, text(l));
        }
        builder.finish_node();
        *next = input.lexemes.len();
    }
}

/// A tree as indented text, one element per line (`KIND@start..end`, and a
/// token's text), for snapshot tests. `name` spells a kind.
pub fn debug_tree<L: rowan::Language>(
    root: &rowan::SyntaxNode<L>,
    name: impl Fn(L::Kind) -> String,
) -> String {
    let mut out = String::new();
    let mut indent = 0usize;
    for event in root.preorder_with_tokens() {
        match event {
            rowan::WalkEvent::Enter(element) => {
                let r = element.text_range();
                let _ = write!(
                    out,
                    "{:indent$}{}@{}..{}",
                    "",
                    name(element.kind()),
                    u32::from(r.start()),
                    u32::from(r.end())
                );
                if let rowan::NodeOrToken::Token(t) = &element {
                    let _ = write!(out, " {:?}", t.text());
                }
                out.push('\n');
                if element.as_node().is_some() {
                    indent += 2;
                }
            }
            rowan::WalkEvent::Leave(element) => {
                if element.as_node().is_some() {
                    indent = indent.saturating_sub(2);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const WS: SyntaxKind = SyntaxKind(0);
    const WORD: SyntaxKind = SyntaxKind(1);
    const L: SyntaxKind = SyntaxKind(2);
    const R: SyntaxKind = SyntaxKind(3);
    const EOF: SyntaxKind = SyntaxKind(4);
    const ERROR: SyntaxKind = SyntaxKind(5);
    const ROOT: SyntaxKind = SyntaxKind(6);
    const GROUP: SyntaxKind = SyntaxKind(7);

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

    /// `( ... )` groups of words, by hand-rolled lexing.
    fn parse(source: &str, max_depth: u32) -> (String, Vec<SyntaxError>) {
        let mut lexemes = Vec::new();
        for (i, c) in source.char_indices() {
            let kind = match c {
                ' ' => WS,
                '(' => L,
                ')' => R,
                _ => WORD,
            };
            lexemes.push(Lexeme {
                kind,
                range: range(i, i + c.len_utf8()),
            });
        }
        let grammar = Grammar {
            eof: EOF,
            error: ERROR,
            trivia: TokenSet::new(&[WS]),
            max_depth,
        };
        let input = Input::new(lexemes, grammar);
        let mut p = Parser::new(&input);
        let root = p.start();
        items(&mut p);
        while !p.at_eof() {
            p.err_and_bump("unexpected");
        }
        root.complete(&mut p, ROOT);
        let parse = build(source, &input, p.finish());
        let node = rowan::SyntaxNode::<Toy>::new_root(parse.green);
        assert_eq!(node.to_string(), source, "lossless");
        let names = ["WS", "WORD", "L", "R", "EOF", "ERROR", "ROOT", "GROUP"];
        (
            debug_tree(&node, |k| names[usize::from(k.0)].to_string()),
            parse.errors,
        )
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
                p.expect(R, "missing )");
                m.complete(p, GROUP);
                p.exit();
            } else {
                return;
            }
        }
    }

    #[test]
    fn trivia_goes_to_the_parent_and_errors_carry_the_expected_set() {
        let (tree, errors) = parse(" a (b c ", 8);
        assert_eq!(
            tree,
            "ROOT@0..8\n  WS@0..1 \" \"\n  WORD@1..2 \"a\"\n  WS@2..3 \" \"\n  GROUP@3..7\n    L@3..4 \"(\"\n    WORD@4..5 \"b\"\n    WS@5..6 \" \"\n    WORD@6..7 \"c\"\n  WS@7..8 \" \"\n"
        );
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "missing )");
        assert_eq!(errors[0].gap, range(7, 8));
        assert!(errors[0].expected.contains(R));
        assert!(errors[0].expected.contains(WORD));
        assert!(!errors[0].expected.contains(WS));
    }

    #[test]
    fn deep_nesting_is_one_error_not_a_stack_overflow() {
        let source = "(".repeat(100_000);
        let (_, errors) = parse(&source, 200);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].message.contains("200"));
    }

    #[test]
    fn unexpected_tokens_are_error_nodes() {
        let (tree, errors) = parse("a ) b", 8);
        assert!(tree.contains("ERROR@2..3"), "{tree}");
        assert_eq!(errors[0].message, "unexpected");
    }

    #[test]
    fn token_set() {
        let s = TokenSet::new(&[WORD, R]).union(TokenSet::new(&[SyntaxKind(200)]));
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![WORD, R]);
        assert!(!s.contains(SyntaxKind(200)));
        assert!(TokenSet::EMPTY.is_empty());
    }
}
