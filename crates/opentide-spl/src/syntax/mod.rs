//! The pure-Rust SPL parser (epic #1219, #1229), built beside the
//! tree-sitter engine until the series' last PR switches production to it:
//! the kinds and the lexer so far. SPL's `KEYWORDS` table is
//! `opentide-highlight`'s `keywords/spl.rs`.

mod kind;
mod lexer;

pub use kind::{Lang, SyntaxKind, SyntaxNode, SyntaxToken};
pub use lexer::lex;
