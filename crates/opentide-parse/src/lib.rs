//! The parsing toolkit of opentide's pure-Rust parsers (ADR 0012), on the
//! rust-analyzer pattern: a [logos] lexer feeds a token [`Input`] (trivia
//! kept for the tree, skipped for lookahead); hand-written grammar functions
//! drive a [`Parser`] that records [`Event`]s through [`Marker`]s; [`build`]
//! turns the events into a lossless [`rowan`] green tree and a list of
//! [`SyntaxError`]s, each with the set of kinds the parser expected there.
//!
//! The toolkit knows no language: kinds are [`rowan::SyntaxKind`] (a `u16`),
//! and a language names the few it needs in a [`Grammar`]. Four guards keep
//! every input finite: the nesting limit ([`Parser::enter`]), the fuel that
//! stops a loop that never consumes ([`ErrorKind::Stalled`]), a replay that
//! never recurses ([`build`]), and the tree depth limit
//! ([`MAX_TREE_DEPTH`]) that keeps dropping a tree off the end of the stack.
//!
//! ```
//! use opentide_parse::{Grammar, Input, Lexeme, Parser, TokenSet, build};
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
//! let input = Input::new(source, lexemes, grammar);
//! let mut p = Parser::new(&input);
//! let root = p.start();
//! let lhs = p.start();
//! p.expect(WORD, "missing a word");
//! let sum = lhs.complete(&mut p, SUM).precede(&mut p);
//! while p.eat(PLUS) {
//!     p.expect(WORD, "missing a word");
//! }
//! sum.complete(&mut p, SUM);
//! root.complete(&mut p, ROOT);
//! let parse = build(&input, p.finish());
//! assert!(parse.errors.is_empty());
//! assert_eq!(parse.green.to_string(), source);
//! ```

// Slicing a `str` by byte index panics off a char boundary, and this crate
// reads user queries: every slice is checked or says why it is safe (#1946;
// the lint moves to `[workspace.lints]` once every crate is clean).
#![warn(clippy::string_slice)]

pub mod ast;
pub mod conformance;

mod debug;
mod green;
mod input;
mod parser;
mod token_set;
mod tree;
mod walk;

pub use debug::{debug_error_kinds, debug_errors, debug_kinds, debug_tree, describe_expected};
pub use input::{Grammar, Input, Lexeme, lex};
pub use parser::{CompletedMarker, ErrorKind, Event, Marker, Parser, TREE_BUDGET};
pub use token_set::TokenSet;
pub use tree::{MAX_TREE_DEPTH, Parse, SyntaxError, build};
pub use walk::{Ancestors, walk_once};

pub use logos;
pub use rowan;

#[cfg(test)]
pub(crate) mod tests {
    /// A rowan language whose kinds are the raw kinds, for unit tests.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub(crate) enum Raw {}

    impl rowan::Language for Raw {
        type Kind = rowan::SyntaxKind;
        fn kind_from_raw(raw: rowan::SyntaxKind) -> rowan::SyntaxKind {
            raw
        }
        fn kind_to_raw(kind: rowan::SyntaxKind) -> rowan::SyntaxKind {
            kind
        }
    }
}
