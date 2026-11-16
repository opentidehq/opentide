//! The [`Parser`] a grammar drives, its [`Marker`]s and the [`Event`]s it
//! records.

use crate::{Input, TokenSet};
use rowan::{SyntaxKind, TextRange};
use std::cell::Cell;

/// Why the toolkit itself recorded an error (the grammar's own errors are
/// [`ErrorKind::Syntax`]): a language maps these to its diagnostic codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// The grammar's error (`expect`, `error`, `err_*`).
    Syntax,
    /// Nesting went past [`Grammar::max_depth`](crate::Grammar::max_depth);
    /// the rest of the input is one error node.
    TooDeep {
        /// The limit.
        limit: u32,
    },
    /// The tree went past [`MAX_TREE_DEPTH`](crate::MAX_TREE_DEPTH) nodes
    /// (a long chain of nodes each wrapped by
    /// [`CompletedMarker::precede`]); the nodes past it are flattened into
    /// the node at the limit, their tokens kept.
    TreeTooDeep {
        /// The limit.
        limit: u32,
    },
    /// The grammar looked ahead without consuming until its fuel ran out: an
    /// engine bug (a loop that never advances). The rest of the input is one
    /// error node; debug builds panic in [`Parser::finish`].
    Stalled,
    /// The events did not form one root node: an engine bug (a marker
    /// completed twice, a token outside the root). The whole source is one
    /// error node; debug builds panic in [`build`](crate::build).
    Unbalanced,
}

/// What a grammar function records; [`build`](crate::build) replays them
/// into a tree.
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
        /// Who recorded it.
        kind: ErrorKind,
        /// The message.
        message: String,
        /// The kinds the parser looked for there.
        expected: TokenSet,
    },
    /// A marker never completed, or one moved by `precede`.
    Tombstone,
}

/// Lookups without progress before the parser stops: a grammar loop that
/// never consumes ends with [`ErrorKind::Stalled`] instead of hanging. Far
/// above what unwinding the deepest legitimate nesting at end of input costs.
const FUEL: u32 = 1 << 24;

/// The message of [`ErrorKind::Stalled`].
const STALLED: &str =
    "the parser stopped making progress here (an engine bug: please report this query)";

/// A grammar's cursor over an [`Input`]: lookahead, consumption, markers,
/// errors with the expected set, the nesting guard and the fuel guard.
#[derive(Debug)]
pub struct Parser<'i> {
    input: &'i Input<'i>,
    pos: usize,
    events: Vec<Event>,
    expected: TokenSet,
    fuel: Cell<u32>,
    full_fuel: u32,
    stalled: Cell<bool>,
    stall_reported: bool,
    /// Whether [`Parser::finish`] panics after a stall: in debug builds, so
    /// tests catch the grammar bug.
    panic_on_stall: bool,
    depth: u32,
    poisoned: bool,
}

impl<'i> Parser<'i> {
    /// A parser at the start of `input`.
    pub fn new(input: &'i Input<'i>) -> Self {
        Self::with_fuel(input, FUEL)
    }

    /// A parser that stops after `fuel` lookups without progress (the default
    /// is 2²⁴): for tests of a grammar's loops.
    pub fn with_fuel(input: &'i Input<'i>, fuel: u32) -> Self {
        Self {
            input,
            pos: 0,
            events: Vec::new(),
            expected: TokenSet::EMPTY,
            fuel: Cell::new(fuel),
            full_fuel: fuel,
            stalled: Cell::new(false),
            stall_reported: false,
            panic_on_stall: cfg!(debug_assertions),
            depth: 0,
            poisoned: false,
        }
    }

    /// The kind of the `n`th significant token ahead; end of input past the
    /// last one, and once the parser has stalled.
    pub fn nth(&self, n: usize) -> SyntaxKind {
        let fuel = self.fuel.get();
        if fuel == 0 {
            self.stalled.set(true);
            return self.input.grammar.eof;
        }
        self.fuel.set(fuel - 1);
        self.input
            .significant(self.pos + n)
            .map_or(self.input.grammar.eof, |l| l.kind)
    }

    /// The kind of the current token.
    pub fn current(&self) -> SyntaxKind {
        self.nth(0)
    }

    /// The text of the `n`th significant token ahead (`""` past the last):
    /// for contextual keywords, which a language lexes as words.
    pub fn nth_text(&self, n: usize) -> &'i str {
        if self.stalled.get() {
            return "";
        }
        self.input
            .significant(self.pos + n)
            .map_or("", |l| self.input.text(l))
    }

    /// The text of the current token.
    pub fn current_text(&self) -> &'i str {
        self.nth_text(0)
    }

    /// Where the current token is; `None` at end of input, and once the
    /// parser has stalled (as [`Parser::nth`]).
    pub fn current_range(&self) -> Option<TextRange> {
        self.nth_range(0)
    }

    /// Where the `n`th significant token ahead is; `None` past the last one,
    /// and once the parser has stalled. With [`Parser::nth`] it lets a
    /// grammar read layout the kinds do not carry: whether two tokens touch
    /// (`nth_range(0)` ends where `nth_range(1)` starts) or what follows a
    /// keyword in the source (a context keyword, Kibana's trailing `or`).
    pub fn nth_range(&self, n: usize) -> Option<TextRange> {
        // Look-ahead like `nth`: it burns fuel, so a loop that only reads
        // ranges stalls instead of hanging.
        let fuel = self.fuel.get();
        if fuel == 0 {
            self.stalled.set(true);
        } else {
            self.fuel.set(fuel - 1);
        }
        if self.stalled.get() {
            return None;
        }
        self.input.significant(self.pos + n).map(|l| l.range)
    }

    /// The source text, for a grammar that must look past the tokens (the
    /// byte after a keyword) with [`Parser::nth_range`].
    pub fn source(&self) -> &'i str {
        self.input.source()
    }

    /// Whether the current token is `kind`; a miss adds `kind` to the
    /// expected set of the next error.
    pub fn at(&mut self, kind: SyntaxKind) -> bool {
        self.at_set(TokenSet::EMPTY.with(kind))
    }

    /// Whether the current token is in `set` (recorded as [`Parser::at`]).
    pub fn at_set(&mut self, set: TokenSet) -> bool {
        self.check_stall();
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
    /// Nothing at end of input, or once the parser has stalled.
    pub fn bump_as(&mut self, kind: SyntaxKind) {
        self.check_stall();
        if self.stalled.get() || self.pos >= self.input.significant.len() {
            return;
        }
        self.events.push(Event::Token { kind });
        self.pos += 1;
        self.expected = TokenSet::EMPTY;
        self.fuel.set(self.full_fuel);
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
    pub fn expect(&mut self, kind: SyntaxKind, message: impl Into<String>) -> bool {
        let found = self.eat(kind);
        if !found {
            self.error(message);
        }
        found
    }

    /// Records an error before the current token, with the expected set.
    /// After the nesting or fuel guard has fired, errors are dropped: one is
    /// enough.
    pub fn error(&mut self, message: impl Into<String>) {
        self.check_stall();
        self.push_error(ErrorKind::Syntax, message.into());
    }

    /// Records an error and wraps the current token in an error node.
    pub fn err_and_bump(&mut self, message: impl Into<String>) {
        let m = self.start();
        self.error(message);
        self.bump();
        m.complete(self, self.input.grammar.error);
    }

    /// Records an error; wraps the current token in an error node unless it
    /// is in `recovery`, where an enclosing rule takes over.
    pub fn err_recover(&mut self, message: impl Into<String>, recovery: TokenSet) {
        if self.at_eof() || recovery.contains(self.current()) {
            self.error(message);
        } else {
            self.err_and_bump(message);
        }
    }

    /// Records an error and wraps the tokens up to one in `stop` (or the end)
    /// in an error node.
    pub fn err_until(&mut self, message: impl Into<String>, stop: TokenSet) {
        let m = self.start();
        self.error(message);
        while !self.at_eof() && !stop.contains(self.current()) {
            self.bump();
        }
        m.complete(self, self.input.grammar.error);
    }

    /// Opens a node.
    pub fn start(&mut self) -> Marker {
        self.check_stall();
        let pos = u32::try_from(self.events.len()).unwrap_or(u32::MAX);
        self.events.push(Event::Tombstone);
        Marker {
            pos,
            child: None,
            armed: true,
        }
    }

    /// One level deeper. Past `max_depth` it records one error, wraps the
    /// rest of the input in an error node, and returns `false`: the caller
    /// returns at once without [`Parser::exit`]. The rules above it unwind
    /// as usual; whether they call `exit` makes no difference, since the
    /// input is consumed and the parser records nothing more.
    ///
    /// It bounds the grammar's recursion. A loop that wraps a node in a new
    /// one ([`CompletedMarker::precede`]) nests the tree without recursing:
    /// [`build`](crate::build) bounds that at
    /// [`MAX_TREE_DEPTH`](crate::MAX_TREE_DEPTH).
    pub fn enter(&mut self) -> bool {
        self.check_stall();
        self.depth = self.depth.saturating_add(1);
        let limit = self.input.grammar.max_depth;
        if self.depth <= limit {
            return true;
        }
        if !self.poisoned {
            let m = self.start();
            self.push_error(
                ErrorKind::TooDeep { limit },
                format!("nesting deeper than {limit} levels"),
            );
            while !self.at_eof() {
                self.bump();
            }
            m.complete(self, self.input.grammar.error);
            self.poisoned = true;
        }
        false
    }

    /// One level up, after an [`Parser::enter`] that returned `true`.
    pub fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Whether the fuel guard has fired.
    pub fn stalled(&self) -> bool {
        self.stalled.get()
    }

    /// The events, for [`build`](crate::build).
    ///
    /// # Panics
    ///
    /// In debug builds, when the parser stalled (a grammar loop that never
    /// consumes): the diagnostic it recorded is what release builds report.
    pub fn finish(mut self) -> Vec<Event> {
        self.check_stall();
        assert!(
            !(self.stall_reported && self.panic_on_stall),
            "opentide-parse: the grammar stopped making progress at significant token {}: a loop that never consumes",
            self.pos
        );
        std::mem::take(&mut self.events)
    }

    fn push_error(&mut self, kind: ErrorKind, message: String) {
        if self.poisoned {
            return;
        }
        self.events.push(Event::Error {
            kind,
            message,
            expected: self.expected,
        });
    }

    /// The first call that may record after the fuel ran out records the
    /// stall, once, and stops every later error.
    fn check_stall(&mut self) {
        if self.stalled.get() && !self.stall_reported {
            self.stall_reported = true;
            self.push_error(ErrorKind::Stalled, STALLED.to_owned());
            self.poisoned = true;
        }
    }
}

/// An open node: [`Marker::complete`] closes it, [`Marker::abandon`] drops
/// it. Dropping it otherwise is a grammar bug, which debug builds panic on.
#[derive(Debug)]
#[must_use = "a node is complete()d or abandon()ed"]
pub struct Marker {
    pos: u32,
    /// The node [`CompletedMarker::precede`] opened this one around: its
    /// `forward_parent` points here until [`Marker::abandon`] clears it.
    child: Option<u32>,
    armed: bool,
}

impl Marker {
    /// Closes the node as `kind`.
    pub fn complete(mut self, p: &mut Parser<'_>, kind: SyntaxKind) -> CompletedMarker {
        self.armed = false;
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

    /// Drops the node; its tokens belong to the enclosing one. A node
    /// [`CompletedMarker::precede`] opened lets go of the node it was to
    /// enclose, which can be preceded again.
    pub fn abandon(mut self, p: &mut Parser<'_>) {
        self.armed = false;
        if let Some(child) = self.child
            && let Some(Event::Start { forward_parent, .. }) = p.events.get_mut(child as usize)
        {
            *forward_parent = None;
        }
        if self.pos as usize + 1 == p.events.len() {
            p.events.pop();
        }
    }
}

impl Drop for Marker {
    fn drop(&mut self) {
        debug_assert!(
            !self.armed || std::thread::panicking(),
            "opentide-parse: a Marker was dropped without complete() or abandon()"
        );
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
    ///
    /// # Panics
    ///
    /// In debug builds, when this node is already preceded by a marker that
    /// was not abandoned (a grammar bug: two nodes would claim it).
    pub fn precede(self, p: &mut Parser<'_>) -> Marker {
        let mut m = p.start();
        if let Some(Event::Start { forward_parent, .. }) = p.events.get_mut(self.pos as usize) {
            debug_assert!(
                forward_parent.is_none(),
                "opentide-parse: a CompletedMarker was preceded twice"
            );
            *forward_parent = Some(m.pos - self.pos);
            m.child = Some(self.pos);
        }
        m
    }

    /// The node's kind.
    pub fn kind(self) -> SyntaxKind {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Grammar, Input, Lexeme, build, input::range};

    const WORD: SyntaxKind = SyntaxKind(1);
    const EOF: SyntaxKind = SyntaxKind(2);
    const ERROR: SyntaxKind = SyntaxKind(3);
    const ROOT: SyntaxKind = SyntaxKind(4);

    fn words(n: usize) -> (String, Vec<Lexeme>) {
        let source = "w".repeat(n);
        let lexemes = (0..n)
            .map(|i| Lexeme {
                kind: WORD,
                range: range(i, i + 1),
            })
            .collect();
        (source, lexemes)
    }

    const GRAMMAR: Grammar = Grammar {
        eof: EOF,
        error: ERROR,
        trivia: TokenSet::EMPTY,
        max_depth: 8,
    };

    /// A loop that looks at the current token and never consumes it.
    fn stuck(p: &mut Parser<'_>) {
        p.bump();
        while !p.at_eof() {
            let _ = p.at(WORD);
        }
    }

    #[test]
    fn a_stall_is_one_diagnostic_and_the_rest_is_an_error_node() {
        let (source, lexemes) = words(3);
        let input = Input::new(&source, lexemes, GRAMMAR);
        let mut p = Parser::with_fuel(&input, 1_000);
        p.panic_on_stall = false;
        let root = p.start();
        stuck(&mut p);
        assert_eq!(
            p.current_range(),
            None,
            "a stalled parser is at end of input"
        );
        p.error("dropped: the stall is the one error");
        root.complete(&mut p, ROOT);
        assert!(p.stalled());
        let parse = build(&input, p.finish());
        assert_eq!(parse.errors.len(), 1, "{:?}", parse.errors);
        assert_eq!(parse.errors[0].kind, ErrorKind::Stalled);
        assert_eq!(parse.errors[0].gap, range(1, 1));
        let tree = rowan::SyntaxNode::<crate::tests::Raw>::new_root(parse.green);
        assert_eq!(tree.to_string(), source, "lossless");
        assert_eq!(tree.last_child().map(|n| n.kind()), Some(ERROR));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "stopped making progress")]
    fn a_stall_panics_in_debug_builds() {
        let (source, lexemes) = words(3);
        let input = Input::new(&source, lexemes, GRAMMAR);
        let mut p = Parser::with_fuel(&input, 1_000);
        let root = p.start();
        stuck(&mut p);
        root.complete(&mut p, ROOT);
        let _ = p.finish();
    }

    #[test]
    fn progress_refuels() {
        // 10 000 tokens, a few lookups each, on 100 units of fuel.
        let (source, lexemes) = words(10_000);
        let input = Input::new(&source, lexemes, GRAMMAR);
        let mut p = Parser::with_fuel(&input, 100);
        let root = p.start();
        while !p.at_eof() {
            let _ = p.at(EOF);
            p.bump();
        }
        root.complete(&mut p, ROOT);
        assert!(!p.stalled());
        assert!(build(&input, p.finish()).errors.is_empty());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "without complete() or abandon()")]
    fn a_forgotten_marker_panics_in_debug_builds() {
        let (source, lexemes) = words(1);
        let input = Input::new(&source, lexemes, GRAMMAR);
        let mut p = Parser::new(&input);
        let _forgotten = p.start();
    }
}
