//! The Exabeam Query Language's kinds, lexer and rowan language.
//!
//! The tree-sitter grammar (`grammars/tree-sitter-opentide-exabeam`) lexes by
//! what its parse state expects next: `abc*` is one free-text word, `abc` then
//! `*` a column and a star, `ASx` after `GROUP-BY a` the keyword `AS` then the
//! table `x`. So this lexer is context free and cuts the source into pieces
//! no token of the grammar ever splits, and the parser ([`crate::cst`]) glues
//! the pieces of each token by the longest match among the tokens its state
//! expects. A run of letters is cut after every keyword it starts with, since
//! a keyword alone can be the token where no name is expected.

use logos::Logos;
use opentide_parse::{Lexeme, TokenSet};
use rowan::{TextRange, TextSize};
use std::cell::Cell;
use std::collections::BTreeSet;

/// A piece of the source, a token of the grammar glued from pieces, or a node
/// of the tree. Pieces come first, so every one fits a [`TokenSet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub(crate) enum SyntaxKind {
    // Pieces.
    Whitespace,
    /// A quoted string, closed: one piece and one token.
    String,
    /// `[A-Za-z_]+`, cut after a keyword it starts with.
    Letters,
    Digits,
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Pipe,
    Colon,
    Eq,
    Lt,
    Gt,
    Bang,
    Dot,
    Star,
    Minus,
    Plus,
    /// Any other character: a piece of a word.
    Other,
    /// A quote that never closes.
    ErrorToken,
    Eof,
    // Tokens of the grammar glued from pieces.
    Keyword,
    EqEq,
    LtEq,
    GtEq,
    NotEqual,
    Identifier,
    Number,
    BareWord,
    TextWord,
    Bound,
    // Nodes.
    SourceFile,
    ForeachStatement,
    Statement,
    SelectClause,
    Column,
    Aggregate,
    FromClause,
    WhereClause,
    AsClause,
    GroupByClause,
    OrderByClause,
    LimitClause,
    Alias,
    TableName,
    Filter,
    OrExpression,
    AndExpression,
    NotExpression,
    Group,
    FieldTerm,
    ContextTerm,
    ContextTable,
    Call,
    FreeText,
    List,
    Range,
    FieldName,
    Error,
}

use SyntaxKind as K;

/// Every kind, in discriminant order: `from_raw` indexes it.
const ALL: [SyntaxKind; 62] = [
    K::Whitespace,
    K::String,
    K::Letters,
    K::Digits,
    K::LParen,
    K::RParen,
    K::LBracket,
    K::RBracket,
    K::LBrace,
    K::RBrace,
    K::Comma,
    K::Pipe,
    K::Colon,
    K::Eq,
    K::Lt,
    K::Gt,
    K::Bang,
    K::Dot,
    K::Star,
    K::Minus,
    K::Plus,
    K::Other,
    K::ErrorToken,
    K::Eof,
    K::Keyword,
    K::EqEq,
    K::LtEq,
    K::GtEq,
    K::NotEqual,
    K::Identifier,
    K::Number,
    K::BareWord,
    K::TextWord,
    K::Bound,
    K::SourceFile,
    K::ForeachStatement,
    K::Statement,
    K::SelectClause,
    K::Column,
    K::Aggregate,
    K::FromClause,
    K::WhereClause,
    K::AsClause,
    K::GroupByClause,
    K::OrderByClause,
    K::LimitClause,
    K::Alias,
    K::TableName,
    K::Filter,
    K::OrExpression,
    K::AndExpression,
    K::NotExpression,
    K::Group,
    K::FieldTerm,
    K::ContextTerm,
    K::ContextTable,
    K::Call,
    K::FreeText,
    K::List,
    K::Range,
    K::FieldName,
    K::Error,
];

impl SyntaxKind {
    /// The raw rowan kind.
    pub(crate) const fn raw(self) -> rowan::SyntaxKind {
        rowan::SyntaxKind(self as u16)
    }

    /// A set of piece kinds.
    pub(crate) const fn set(kinds: &[SyntaxKind]) -> TokenSet {
        let mut set = TokenSet::EMPTY;
        let mut i = 0;
        while i < kinds.len() {
            set = set.with(kinds[i].raw());
            i += 1;
        }
        set
    }

    /// The kind of a raw rowan kind (`Error` for one that is none of ours).
    pub(crate) fn from_raw(raw: rowan::SyntaxKind) -> Self {
        ALL.get(usize::from(raw.0)).copied().unwrap_or(K::Error)
    }

    /// The name of the kind: the tree-sitter rule's name for the ones the
    /// grammar has, which the corpus fixtures (`prod:<rule>`) name.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            K::Whitespace => "whitespace",
            K::String => "string",
            K::Letters => "letters",
            K::Digits => "digits",
            K::LParen => "(",
            K::RParen => ")",
            K::LBracket => "[",
            K::RBracket => "]",
            K::LBrace => "{",
            K::RBrace => "}",
            K::Comma => ",",
            K::Pipe => "|",
            K::Colon => ":",
            K::Eq => "=",
            K::Lt => "<",
            K::Gt => ">",
            K::Bang => "!",
            K::Dot => ".",
            K::Star => "*",
            K::Minus => "-",
            K::Plus => "+",
            K::Other => "other",
            K::ErrorToken => "error_token",
            K::Eof => "end of input",
            K::Keyword => "keyword",
            K::EqEq => "==",
            K::LtEq => "<=",
            K::GtEq => ">=",
            K::NotEqual => "not_equal",
            K::Identifier => "identifier",
            K::Number => "number",
            K::BareWord => "bare_word",
            K::TextWord => "text_word",
            K::Bound => "bound",
            K::SourceFile => "source_file",
            K::ForeachStatement => "foreach_statement",
            K::Statement => "statement",
            K::SelectClause => "select_clause",
            K::Column => "column",
            K::Aggregate => "aggregate",
            K::FromClause => "from_clause",
            K::WhereClause => "where_clause",
            K::AsClause => "as_clause",
            K::GroupByClause => "group_by_clause",
            K::OrderByClause => "order_by_clause",
            K::LimitClause => "limit_clause",
            K::Alias => "alias",
            K::TableName => "table_name",
            K::Filter => "filter",
            K::OrExpression => "or_expression",
            K::AndExpression => "and_expression",
            K::NotExpression => "not_expression",
            K::Group => "group",
            K::FieldTerm => "field_term",
            K::ContextTerm => "context_term",
            K::ContextTable => "context_table",
            K::Call => "call",
            K::FreeText => "free_text",
            K::List => "list",
            K::Range => "range",
            K::FieldName => "field_name",
            K::Error => "ERROR",
        }
    }
}

/// The rowan language of Exabeam queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Exabeam {}

impl rowan::Language for Exabeam {
    type Kind = SyntaxKind;
    fn kind_from_raw(raw: rowan::SyntaxKind) -> SyntaxKind {
        SyntaxKind::from_raw(raw)
    }
    fn kind_to_raw(kind: SyntaxKind) -> rowan::SyntaxKind {
        kind.raw()
    }
}

/// A node of the tree.
pub(crate) type SyntaxNode = rowan::SyntaxNode<Exabeam>;
/// A token of the tree.
pub(crate) type SyntaxToken = rowan::SyntaxToken<Exabeam>;

/// The grammar's keywords, upper case; they match in any case.
pub(crate) const KEYWORDS: [&str; 16] = [
    "FOREACH", "SELECT", "DISTINCT", "AS", "FROM", "WHERE", "GROUP-BY", "ORDER-BY", "ASC", "DESC",
    "LIMIT", "OR", "AND", "NOT", "IN", "TO",
];

/// The pieces. Whitespace is the grammar's `extras` (`\s`, which its
/// generator reads as ASCII whitespace). No regex repeats a group: a class
/// repeated is a loop, a group repeated recurses per repetition (see the
/// crate's `tests/long_runs.rs`).
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
enum Piece {
    #[regex(r"[ \t\n\x0b\x0c\r]+")]
    Whitespace,
    #[token("\"", |lex| quoted(lex, b'"'))]
    #[token("'", |lex| quoted(lex, b'\''))]
    String,
    #[regex(r"[A-Za-z_]+")]
    Letters,
    #[regex(r"[0-9]+")]
    Digits,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
    #[token(",")]
    Comma,
    #[token("|")]
    Pipe,
    #[token(":")]
    Colon,
    #[token("=")]
    Eq,
    #[token("<")]
    Lt,
    #[token(">")]
    Gt,
    #[token("!")]
    Bang,
    #[token(".")]
    Dot,
    #[token("*")]
    Star,
    #[token("-")]
    Minus,
    #[token("+")]
    Plus,
    /// One character: a run of non-ASCII ones would be a repeated group of
    /// UTF-8 sequences.
    #[regex("[^ \t\n\x0b\x0c\r\"'A-Za-z_0-9()\\[\\]{},|:=<>!.*+\\-]")]
    Other,
}

thread_local! {
    /// Per delimiter (`"`, `'`), the last scan that found no closing quote,
    /// as `(remaining, stop)`: the bytes left after the opening quote, and
    /// where it stopped (bytes left; `0` at the end of the text). Lengths
    /// to the end, because opentide-parse restarts logos on the rest of the
    /// text after an error: the offset of a fresh lexer is not the source's.
    static UNCLOSED: Cell<[(usize, usize); 2]> = const { Cell::new([(0, 0); 2]) };
}

/// The rest of a quoted string after its opening `delimiter`: a backslash
/// escapes the character after it, whatever it is; a NUL ends no string, as
/// the grammar's lexer reads it. Scanned by a loop, for the reason of
/// [`Piece`]. Unclosed, the quote alone is an error.
///
/// Whether a quote byte is escaped depends on its place alone (the run of
/// backslashes before it), and every scan starts after a quote: a scan from
/// a quote inside a failed scan's range reaches the same stop, and fails.
/// So a failure is remembered, and `\"\"\"…` without a closing quote, an
/// error at each quote, is read once rather than once per quote.
fn quoted(lex: &mut logos::Lexer<'_, Piece>, delimiter: u8) -> bool {
    let rest = lex.remainder().as_bytes();
    let slot = usize::from(delimiter == b'\'');
    let (failed_from, failed_stop) = UNCLOSED.with(Cell::get)[slot];
    if rest.len() <= failed_from && rest.len() > failed_stop {
        return false;
    }
    let mut i = 0;
    while let Some(&b) = rest.get(i) {
        if b == delimiter {
            lex.bump(i + 1);
            return true;
        }
        if b == 0 {
            break;
        }
        // A backslash takes the next character, which may be several bytes:
        // skipping one byte lands inside it, and a continuation byte is
        // never a delimiter. It takes no NUL.
        i += if b == b'\\' && rest.get(i + 1) != Some(&0) {
            2
        } else {
            1
        };
    }
    let stop = rest.len() - i.min(rest.len());
    UNCLOSED.with(|u| {
        let mut all = u.get();
        all[slot] = (rest.len(), stop);
        u.set(all);
    });
    false
}

/// Lexes `source`. A byte-order mark at its start is whitespace: tree-sitter
/// skips one there.
pub(crate) fn lex(source: &str) -> Vec<Lexeme> {
    UNCLOSED.with(|u| u.set([(0, 0); 2]));
    let bom = if source.starts_with('\u{feff}') {
        '\u{feff}'.len_utf8()
    } else {
        0
    };
    let mut pieces = Vec::new();
    if bom > 0 {
        pieces.push(Lexeme {
            kind: K::Whitespace.raw(),
            range: range(0, bom),
        });
    }
    let shift = TextSize::from(u32::try_from(bom).unwrap_or(0));
    let rest = opentide_parse::lex::<Piece>(source.get(bom..).unwrap_or(""), |piece, _| {
        match piece {
            Ok(Piece::Whitespace) => K::Whitespace,
            Ok(Piece::String) => K::String,
            Ok(Piece::Letters) => K::Letters,
            Ok(Piece::Digits) => K::Digits,
            Ok(Piece::LParen) => K::LParen,
            Ok(Piece::RParen) => K::RParen,
            Ok(Piece::LBracket) => K::LBracket,
            Ok(Piece::RBracket) => K::RBracket,
            Ok(Piece::LBrace) => K::LBrace,
            Ok(Piece::RBrace) => K::RBrace,
            Ok(Piece::Comma) => K::Comma,
            Ok(Piece::Pipe) => K::Pipe,
            Ok(Piece::Colon) => K::Colon,
            Ok(Piece::Eq) => K::Eq,
            Ok(Piece::Lt) => K::Lt,
            Ok(Piece::Gt) => K::Gt,
            Ok(Piece::Bang) => K::Bang,
            Ok(Piece::Dot) => K::Dot,
            Ok(Piece::Star) => K::Star,
            Ok(Piece::Minus) => K::Minus,
            Ok(Piece::Plus) => K::Plus,
            Ok(Piece::Other) => K::Other,
            Err(()) => K::ErrorToken,
        }
        .raw()
    });
    pieces.extend(rest.into_iter().map(|l| Lexeme {
        kind: l.kind,
        range: l.range + shift,
    }));
    cut_after_keywords(source, pieces)
}

/// The length of the keyword `source` starts with at `at`, in any case: every
/// one, since the parser's state decides which of them it reads.
fn keyword_ends(source: &str, at: usize) -> impl Iterator<Item = usize> + '_ {
    let rest = source.as_bytes().get(at..).unwrap_or_default();
    KEYWORDS.iter().filter_map(move |k| {
        let head = rest.get(..k.len())?;
        head.eq_ignore_ascii_case(k.as_bytes())
            .then_some(at + k.len())
    })
}

/// Cuts each run of letters after every keyword it, or a piece of it, starts
/// with: `ASCx` is `AS`, `C`, `x` (after `GROUP-BY a`, `AS` then the table
/// `Cx`; after `ORDER-BY a`, `ASC` then nothing valid). A keyword that runs
/// over a `-` (`GROUP-BY`) cuts the run of letters it ends in.
fn cut_after_keywords(source: &str, pieces: Vec<Lexeme>) -> Vec<Lexeme> {
    let mut out = Vec::with_capacity(pieces.len());
    // Cuts that fall past the piece being split, in a later run of letters.
    let mut pending: BTreeSet<usize> = BTreeSet::new();
    for piece in pieces {
        let (start, end) = (
            usize::from(piece.range.start()),
            usize::from(piece.range.end()),
        );
        pending = pending.split_off(&(start + 1));
        if piece.kind != K::Letters.raw() {
            out.push(piece);
            continue;
        }
        // Every start of a piece is where a keyword may start: the run's,
        // and each cut's. They are visited in order, so each cut is a start
        // once.
        let mut cuts: BTreeSet<usize> = pending.range(..end).copied().collect();
        cuts.insert(start);
        let mut at = Some(start);
        while let Some(from) = at {
            for cut in keyword_ends(source, from) {
                if cut < end {
                    cuts.insert(cut);
                } else if cut > end {
                    pending.insert(cut);
                }
            }
            at = cuts.range(from + 1..).next().copied();
        }
        cuts.insert(end);
        let mut from = start;
        for &cut in cuts.iter().skip(1) {
            out.push(Lexeme {
                kind: piece.kind,
                range: range(from, cut),
            });
            from = cut;
        }
    }
    out
}

/// A range of byte offsets, clamped to `u32` as opentide-parse clamps its
/// own (`TextSize`).
fn range(start: usize, end: usize) -> TextRange {
    let size = |n: usize| TextSize::from(u32::try_from(n).unwrap_or(u32::MAX));
    TextRange::new(size(start), size(end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pieces(source: &str) -> Vec<(SyntaxKind, &str)> {
        lex(source)
            .iter()
            .map(|l| (SyntaxKind::from_raw(l.kind), &source[l.range]))
            .collect()
    }

    #[test]
    fn letters_digits_and_punctuation_are_pieces() {
        assert_eq!(
            pieces("a.b_c-1:<=@x é"),
            vec![
                (K::Letters, "a"),
                (K::Dot, "."),
                (K::Letters, "b_c"),
                (K::Minus, "-"),
                (K::Digits, "1"),
                (K::Colon, ":"),
                (K::Lt, "<"),
                (K::Eq, "="),
                (K::Other, "@"),
                (K::Letters, "x"),
                (K::Whitespace, " "),
                (K::Other, "é"),
            ]
        );
    }

    #[test]
    fn a_run_of_letters_is_cut_after_each_keyword_it_starts_with() {
        assert_eq!(
            pieces("ASCx"),
            vec![(K::Letters, "AS"), (K::Letters, "C"), (K::Letters, "x")]
        );
        assert_eq!(pieces("Android")[0], (K::Letters, "And"));
        assert_eq!(pieces("ASAS").len(), 2);
        assert_eq!(pieces("abc"), vec![(K::Letters, "abc")]);
        // `GROUP-BY` ends inside `BYx`.
        assert_eq!(
            pieces("group-byx"),
            vec![
                (K::Letters, "group"),
                (K::Minus, "-"),
                (K::Letters, "by"),
                (K::Letters, "x"),
            ]
        );
        // A keyword's start must be a piece's start.
        assert_eq!(pieces("xAND"), vec![(K::Letters, "xAND")]);
    }

    #[test]
    fn strings_close_unless_escaped() {
        assert_eq!(pieces(r#""a\"b" 'c'"#)[0], (K::String, r#""a\"b""#));
        assert_eq!(pieces(r#""a\\""#), vec![(K::String, r#""a\\""#)]);
        assert_eq!(pieces("\"\\é\""), vec![(K::String, "\"\\é\"")]);
        assert_eq!(pieces("\"abc")[0], (K::ErrorToken, "\""));
        assert_eq!(pieces("'it's'")[0], (K::String, "'it'"));
        assert_eq!(pieces("\"a\nb\"")[0], (K::String, "\"a\nb\""));
    }

    #[test]
    fn a_nul_ends_no_string() {
        assert_eq!(pieces("\"a\0b\"")[0], (K::ErrorToken, "\""));
        assert_eq!(pieces("\"a\\\0\"")[0], (K::ErrorToken, "\""));
        // A quote past the NUL opens a string of its own.
        let after = pieces("\"\0 'b'");
        assert_eq!(after.last(), Some(&(K::String, "'b'")));
        assert_eq!(pieces("'\0' \"x\"")[4], (K::String, "\"x\""));
    }

    /// An unclosed quote is an error and lexing restarts after it: without
    /// the memory of a failed scan, each of these quotes scanned to the end.
    #[test]
    fn escaped_quotes_never_closed_are_read_once() {
        for quote in ['"', '\''] {
            let source = format!("\\{quote}").repeat(500_000);
            let started = std::time::Instant::now();
            let lexed = lex(&source);
            assert!(
                started.elapsed() < std::time::Duration::from_secs(20),
                "{quote}: {:?}",
                started.elapsed()
            );
            assert_eq!(lexed.len(), 1_000_000);
            assert!(
                lexed
                    .iter()
                    .all(|l| SyntaxKind::from_raw(l.kind) != K::String)
            );
        }
        // The other delimiter's strings still close.
        assert_eq!(pieces("\\\" 'a'").last(), Some(&(K::String, "'a'")));
    }

    #[test]
    fn keyword_cuts_follow_order_by_and_chain_across_runs() {
        assert_eq!(
            pieces("ORDER-BYDESC"),
            vec![
                (K::Letters, "OR"),
                (K::Letters, "DER"),
                (K::Minus, "-"),
                (K::Letters, "BY"),
                (K::Letters, "DESC"),
            ]
        );
        assert_eq!(
            pieces("group-byASx"),
            vec![
                (K::Letters, "group"),
                (K::Minus, "-"),
                (K::Letters, "by"),
                (K::Letters, "AS"),
                (K::Letters, "x"),
            ]
        );
    }

    #[test]
    fn the_pieces_tile_the_source() {
        let source = "é\u{a0}a:\"x\" 'y AND«ORDER-BY» \u{3000}1.5";
        let mut end = 0;
        for l in lex(source) {
            assert_eq!(usize::from(l.range.start()), end);
            end = usize::from(l.range.end());
        }
        assert_eq!(end, source.len());
    }

    #[test]
    fn a_byte_order_mark_at_the_start_is_whitespace() {
        assert_eq!(
            pieces("\u{feff}AS x"),
            vec![
                (K::Whitespace, "\u{feff}"),
                (K::Letters, "AS"),
                (K::Whitespace, " "),
                (K::Letters, "x"),
            ]
        );
        assert_eq!(pieces("a\u{feff}")[1], (K::Other, "\u{feff}"));
    }

    #[test]
    fn whitespace_is_ascii() {
        assert_eq!(pieces("\u{a0}")[0], (K::Other, "\u{a0}"));
        assert_eq!(pieces("\x0b\x0c")[0], (K::Whitespace, "\x0b\x0c"));
    }

    #[test]
    fn every_kind_round_trips_and_pieces_fit_a_set() {
        for (i, kind) in ALL.iter().enumerate() {
            assert_eq!(usize::from(kind.raw().0), i);
            assert_eq!(SyntaxKind::from_raw(kind.raw()), *kind);
        }
        assert!(usize::from(TokenSet::CAPACITY) > ALL.len());
    }
}
