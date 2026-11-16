//! The YARA-L parser on `opentide-parse` (#1227): recursive descent, with the
//! expressions by precedence climbing. `yaral.ungram` is the shape of the tree
//! it builds.
//!
//! The lexer reads every reserved word as its keyword and the contextual ones
//! (`every`, `first`, `cross`, `join`, `graph_*`) as names; where the grammar
//! takes a contextual word the parser re-kinds it ([`P::bump_word`]), and
//! where it wants a name it takes any word (in the sections).

mod expr;
#[cfg(test)]
mod tests;

use crate::lexer::lex;
use crate::syntax::SyntaxKind as K;
use opentide_parse::{CompletedMarker, Grammar, Input, Marker, Parse, Parser, TokenSet, build};

/// The deepest nesting of expressions the parser takes: a thousand
/// parentheses (the floor of `deep_queries`) and the statement around them.
/// Past it: one error and the rest of the input in one error node.
const MAX_DEPTH: u32 = 1_100;

const GRAMMAR: Grammar = Grammar {
    eof: K::EOF.raw(),
    error: K::ERROR.raw(),
    trivia: TokenSet::new(&[K::WHITESPACE.raw(), K::COMMENT.raw()]),
    max_depth: MAX_DEPTH,
};

/// Parses `source` into a lossless tree and its syntax errors.
pub(crate) fn parse(source: &str) -> Parse {
    let input = Input::new(source, lex(source), GRAMMAR);
    let mut p = P(Parser::new(&input));
    source_file(&mut p);
    build(&input, p.0.finish())
}

/// The toolkit's parser, spoken in this language's kinds.
pub(crate) struct P<'i>(Parser<'i>);

impl P<'_> {
    pub(crate) fn nth(&self, n: usize) -> K {
        K::from_raw(self.0.nth(n))
    }

    pub(crate) fn current(&self) -> K {
        self.nth(0)
    }

    pub(crate) fn at(&mut self, kind: K) -> bool {
        self.0.at(kind.raw())
    }

    pub(crate) fn at_eof(&self) -> bool {
        self.0.at_eof()
    }

    pub(crate) fn eat(&mut self, kind: K) -> bool {
        self.0.eat(kind.raw())
    }

    pub(crate) fn bump(&mut self) {
        self.0.bump();
    }

    /// Consumes `kind`, or records "expected ..." without consuming.
    pub(crate) fn expect(&mut self, kind: K) -> bool {
        let found = self.0.eat(kind.raw());
        if !found {
            self.0.error(format!("expected {}", kind.describe()));
        }
        found
    }

    pub(crate) fn error(&mut self, message: &str) {
        self.0.error(message);
    }

    pub(crate) fn err_until(&mut self, message: &str, stop: TokenSet) {
        self.0.err_until(message, stop);
    }

    pub(crate) fn start(&mut self) -> Marker {
        self.0.start()
    }

    pub(crate) fn enter(&mut self) -> bool {
        self.0.enter()
    }

    pub(crate) fn exit(&mut self) {
        self.0.exit();
    }

    pub(crate) fn done(&mut self, marker: Marker, kind: K) -> CompletedMarker {
        marker.complete(&mut self.0, kind.raw())
    }

    pub(crate) fn abandon(&mut self, marker: Marker) {
        marker.abandon(&mut self.0);
    }

    pub(crate) fn precede(&mut self, done: CompletedMarker) -> Marker {
        done.precede(&mut self.0)
    }

    /// Whether the token `n` ahead is the contextual word `word`, in any case.
    pub(crate) fn at_word(&self, n: usize, word: &str) -> bool {
        self.nth(n) == K::IDENT && self.0.nth_text(n).eq_ignore_ascii_case(word)
    }

    /// Consumes the contextual word at the cursor as the keyword `kind`.
    pub(crate) fn bump_word(&mut self, kind: K) {
        self.0.bump_as(kind.raw());
    }
}

/// `SourceFile`. A search for now: its events, with no `events:` label.
fn source_file(p: &mut P<'_>) {
    let file = p.start();
    if expr::at_statement_start(p) {
        let query = p.start();
        let events = p.start();
        while expr::at_statement_start(p) {
            expr::statement(p);
        }
        p.done(events, K::SEARCH_EVENTS);
        p.done(query, K::SEARCH_QUERY);
    }
    if !p.at_eof() {
        p.err_until("unexpected text", TokenSet::EMPTY);
    }
    p.done(file, K::SOURCE_FILE);
}
