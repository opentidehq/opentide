//! The token source: [`lex`] over a logos lexer, and the [`Input`] the
//! parser reads.

use crate::TokenSet;
use rowan::{SyntaxKind, TextRange, TextSize};

/// The kinds a language gives the toolkit.
#[derive(Clone, Copy, Debug)]
pub struct Grammar {
    /// What [`Parser::current`](crate::Parser::current) returns past the
    /// last token.
    pub eof: SyntaxKind,
    /// The node that wraps unexpected tokens.
    pub error: SyntaxKind,
    /// Whitespace and comments: in the tree, never seen by the grammar.
    pub trivia: TokenSet,
    /// The deepest nesting [`Parser::enter`](crate::Parser::enter) allows;
    /// past it the rest of the input is one error node and one diagnostic,
    /// never a stack overflow. A language sets it at or above the depth its
    /// `deep_queries` floor requires (what its tree-sitter engine accepted).
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
/// logos's error) and its text to a kind.
///
/// Every byte ends up in one lexeme, so `T` must not `skip` anything:
/// whitespace and comments are tokens (trivia). An error is one character,
/// and lexing resumes after it with a fresh lexer (as tree-sitter's lexer
/// skips a character): logos does not backtrack, so its error span would
/// swallow a valid prefix of what follows. A language with lexer modes
/// (`morph`, or a sub-lexer for strings) drives logos itself and builds the
/// lexemes the same way.
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
            let start = base + span.start;
            let error = token.is_err();
            let end = if error {
                // One character: the next character boundary after `start`.
                source.ceil_char_boundary(start + 1)
            } else {
                base + span.end
            };
            debug_assert!(
                out.last()
                    .is_none_or(|l: &Lexeme| l.range.end() == offset(start)),
                "the lexer skipped bytes before {start}: a lossless lexer has no `skip`"
            );
            out.push(Lexeme {
                kind: kind(token, source.get(start..end).unwrap_or("")),
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

/// A byte offset as a [`TextSize`]; rowan's sizes are `u32`, and a source
/// past 4 GiB is clamped rather than wrapped.
pub(crate) fn offset(n: usize) -> TextSize {
    TextSize::from(u32::try_from(n).unwrap_or(u32::MAX))
}

/// `start..end` as a [`TextRange`], never inverted.
pub(crate) fn range(start: usize, end: usize) -> TextRange {
    TextRange::new(offset(start), offset(end.max(start)))
}

/// Whether `lexemes` tile `source` ([`Input::new`]).
fn tiles(source: &str, lexemes: &[Lexeme]) -> bool {
    let mut end = 0usize;
    for l in lexemes {
        let (start, stop) = (usize::from(l.range.start()), usize::from(l.range.end()));
        if start != end || !source.is_char_boundary(stop) {
            return false;
        }
        end = stop;
    }
    end == source.len()
}

/// A source and its lexemes, with the significant ones (not trivia) indexed
/// for the parser's lookahead.
#[derive(Debug)]
pub struct Input<'s> {
    pub(crate) source: &'s str,
    pub(crate) lexemes: Vec<Lexeme>,
    pub(crate) significant: Vec<usize>,
    pub(crate) grammar: Grammar,
}

impl<'s> Input<'s> {
    /// The input of `source`'s `lexemes`, which must tile it: in source
    /// order, contiguous, from 0 to `source.len()`, on char boundaries.
    /// Debug builds check it; a release build given lexemes that do not tile
    /// the source builds a tree that misses bytes.
    pub fn new(source: &'s str, lexemes: Vec<Lexeme>, grammar: Grammar) -> Self {
        debug_assert!(
            tiles(source, &lexemes),
            "the lexemes do not tile the source (in order, contiguous, 0 to its length, on char boundaries)"
        );
        let significant = (0..lexemes.len())
            .filter(|&i| !grammar.trivia.contains(lexemes[i].kind))
            .collect();
        Self {
            source,
            lexemes,
            significant,
            grammar,
        }
    }

    /// The source text.
    pub fn source(&self) -> &'s str {
        self.source
    }

    /// Every lexeme, trivia included.
    pub fn lexemes(&self) -> &[Lexeme] {
        &self.lexemes
    }

    /// The grammar's kinds.
    pub fn grammar(&self) -> Grammar {
        self.grammar
    }

    /// The text of `lexeme`.
    pub(crate) fn text(&self, lexeme: &Lexeme) -> &'s str {
        self.source
            .get(std::ops::Range::<usize>::from(lexeme.range))
            .unwrap_or("")
    }

    /// The `n`th significant lexeme.
    pub(crate) fn significant(&self, n: usize) -> Option<&Lexeme> {
        self.significant.get(n).and_then(|&i| self.lexemes.get(i))
    }
}
