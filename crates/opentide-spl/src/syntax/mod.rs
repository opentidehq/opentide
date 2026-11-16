//! The pure-Rust SPL parser (epic #1219, #1229): the logos lexer, the
//! grammar on `opentide-parse`, and the analysis on its tree, which
//! `crate::analyze` runs. SPL's `KEYWORDS` table is `opentide-highlight`'s
//! `keywords/spl.rs`.

mod analyze;
mod expr;
mod kind;
mod lexer;
mod parser;
mod rest;
mod search;
mod stats;
mod table;

pub use analyze::analyze;
pub use kind::{Lang, SyntaxKind, SyntaxNode, SyntaxToken};
pub use lexer::lex;
pub use parser::{GRAMMAR, MAX_DEPTH, parse};
