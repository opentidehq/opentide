//! The pure-Rust SPL parser (epic #1219, #1229), built beside the
//! tree-sitter engine until the series' last PR switches production to it:
//! the kinds, the lexer and the grammar of the pipeline
//! and of search terms so far.

mod expr;
mod kind;
mod lexer;
mod parser;
mod search;

pub use kind::{Lang, SyntaxKind, SyntaxNode, SyntaxToken};
pub use lexer::lex;
pub use parser::{GRAMMAR, parse};
