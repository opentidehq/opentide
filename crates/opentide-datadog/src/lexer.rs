//! The lexer: a logos token type over the whole text, with no modes.
//!
//! The search syntax glues a term out of whatever touches (`web-*`, `waiting\ un*`,
//! `system:serviceaccount:x` in a value), so the lexer cuts small pieces and the parser glues
//! the ones that touch. A word is a run of the characters a term may hold: not whitespace, not
//! ``( ) [ ] { } " : \ ! ~ ^ < > * ? ,``, and not starting with `- + =` (VRL's `TERM_START_CHAR`
//! and `TERM_CHAR`, with `*`, `?`, `:` and `,` cut out as tokens of their own).
//!
//! Phrases and escapes are scanned by callbacks, never by a repeated regex group: a logos regex
//! that repeats a group recurses once per repetition, and every token class must hold a
//! million characters on a 1 MB stack (`tests/parser_depth.rs`).

use crate::syntax::SyntaxKind as K;
use logos::Logos;
use opentide_parse::Lexeme;

/// The pieces of a query.
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
enum Piece {
    /// VRL's `WHITESPACE`: space, tab, carriage return, line feed (ASCII bytes only, so the
    /// repetition is a byte loop).
    #[regex(r"[ \t\r\n]+")]
    Whitespace,
    /// A word's first character; [`word`] scans the rest. A repeated class of multi-byte
    /// characters recursed once per character in logos and overflowed a 1 MB stack.
    #[regex(r#"[^ \t\r\n()\[\]{}":\\!~^<>*?,=+\-]"#, word)]
    Word,
    #[token("\\", escape)]
    Escape,
    /// `true` when the closing quote was found.
    #[token("\"", phrase)]
    Phrase(bool),
    #[token("*")]
    Star,
    #[token("?")]
    Question,
    #[token(":")]
    Colon,
    #[token(",")]
    Comma,
    #[token("-")]
    Minus,
    #[token("+")]
    Plus,
    #[token("=")]
    Eq,
    #[token("!")]
    Bang,
    #[token("~")]
    Tilde,
    #[token("^")]
    Caret,
    #[token("<")]
    Lt,
    #[token("<=")]
    LtEq,
    #[token(">")]
    Gt,
    #[token(">=")]
    GtEq,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("[")]
    LBrack,
    #[token("]")]
    RBrack,
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
}

/// The rest of a word after its first character: every character up to whitespace or a
/// character a term cannot hold unescaped.
fn word(lex: &mut logos::Lexer<'_, Piece>) {
    let end = lex
        .remainder()
        .find(|c: char| {
            matches!(
                c,
                ' ' | '\t'
                    | '\r'
                    | '\n'
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '"'
                    | ':'
                    | '\\'
                    | '!'
                    | '~'
                    | '^'
                    | '<'
                    | '>'
                    | '*'
                    | '?'
                    | ','
            )
        })
        .unwrap_or(lex.remainder().len());
    lex.bump(end);
}

/// A backslash takes the one character after it, whatever it is (a space, a line break, a
/// quote). A backslash at the end of the text takes nothing: an error.
fn escape(lex: &mut logos::Lexer<'_, Piece>) -> bool {
    match lex.remainder().chars().next() {
        Some(c) => {
            lex.bump(c.len_utf8());
            true
        }
        None => false,
    }
}

/// The rest of a phrase after its opening quote: a backslash escapes the character after it.
/// With no closing quote the phrase runs to the end of the text, so an unclosed quote is read
/// once, never rescanned from each later quote.
fn phrase(lex: &mut logos::Lexer<'_, Piece>) -> bool {
    let rest = lex.remainder().as_bytes();
    let mut i = 0;
    while let Some(&b) = rest.get(i) {
        match b {
            b'"' => {
                lex.bump(i + 1);
                return true;
            }
            // The escaped character may be several bytes: its continuation bytes are never a
            // quote, so stepping over its first byte is enough.
            b'\\' => i += 2,
            _ => i += 1,
        }
    }
    lex.bump(rest.len());
    false
}

/// Lexes `source` into lexemes that tile it. A byte-order mark at the start is whitespace, as
/// an editor shows the text; anywhere else it is a term's character.
pub(crate) fn lex(source: &str) -> Vec<Lexeme> {
    let bom = if source.starts_with('\u{feff}') {
        '\u{feff}'.len_utf8()
    } else {
        0
    };
    let mut out = Vec::new();
    let shift = rowan::TextSize::from(u32::try_from(bom).unwrap_or(0));
    if bom > 0 {
        out.push(Lexeme {
            kind: K::WHITESPACE.raw(),
            range: rowan::TextRange::up_to(shift),
        });
    }
    let rest = source.get(bom..).unwrap_or("");
    out.extend(pieces(rest).into_iter().map(|l| Lexeme {
        kind: l.kind,
        range: l.range + shift,
    }));
    out
}

/// The lexemes of `source`, from its first byte.
fn pieces(source: &str) -> Vec<Lexeme> {
    opentide_parse::lex::<Piece>(source, |piece, _| {
        match piece {
            Ok(Piece::Whitespace) => K::WHITESPACE,
            Ok(Piece::Word) => K::WORD,
            Ok(Piece::Escape) => K::ESCAPE,
            Ok(Piece::Phrase(true)) => K::PHRASE_TOKEN,
            Ok(Piece::Phrase(false)) => K::UNCLOSED_PHRASE,
            Ok(Piece::Star) => K::STAR,
            Ok(Piece::Question) => K::QUESTION,
            Ok(Piece::Colon) => K::COLON,
            Ok(Piece::Comma) => K::COMMA,
            Ok(Piece::Minus) => K::MINUS,
            Ok(Piece::Plus) => K::PLUS,
            Ok(Piece::Eq) => K::EQ,
            Ok(Piece::Bang) => K::BANG,
            Ok(Piece::Tilde) => K::TILDE,
            Ok(Piece::Caret) => K::CARET,
            Ok(Piece::Lt) => K::LT,
            Ok(Piece::LtEq) => K::LT_EQ,
            Ok(Piece::Gt) => K::GT,
            Ok(Piece::GtEq) => K::GT_EQ,
            Ok(Piece::LParen) => K::L_PAREN,
            Ok(Piece::RParen) => K::R_PAREN,
            Ok(Piece::LBrack) => K::L_BRACK,
            Ok(Piece::RBrack) => K::R_BRACK,
            Ok(Piece::LBrace) => K::L_BRACE,
            Ok(Piece::RBrace) => K::R_BRACE,
            Err(()) => K::ERROR_TOKEN,
        }
        .raw()
    })
}

/// Whether `text` is a number as VRL reads one (`-?\d+(\.\d+)?(E-?\d+(\.\d+)?)?`), optionally
/// followed by a duration unit (`100ms`, `5m`, `2days`). The sign is the lexer's `-` token, so
/// a word never starts with one; an exponent's sign is inside the word (`1E-5`).
pub(crate) fn is_number(text: &str) -> bool {
    /// The duration units of the search syntax, longest first where one is a prefix of another.
    const UNITS: [&str; 12] = [
        "days", "day", "min", "ms", "ns", "us", "µs", "s", "m", "h", "d", "w",
    ];
    fn digits(s: &[u8], mut i: usize) -> Option<usize> {
        let start = i;
        while s.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        (i > start).then_some(i)
    }
    /// `\d+(\.\d+)?` from `i`: where it ends.
    fn decimal(s: &[u8], i: usize) -> Option<usize> {
        let i = digits(s, i)?;
        if s.get(i) == Some(&b'.') {
            return digits(s, i + 1);
        }
        Some(i)
    }
    let s = text.as_bytes();
    let Some(mut i) = decimal(s, 0) else {
        return false;
    };
    if s.get(i) == Some(&b'E') {
        let sign = usize::from(s.get(i + 1) == Some(&b'-'));
        if let Some(end) = decimal(s, i + 1 + sign) {
            i = end;
        }
    }
    let rest = text.get(i..).unwrap_or("");
    rest.is_empty() || UNITS.contains(&rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<(K, &str)> {
        lex(source)
            .into_iter()
            .map(|l| {
                let range = std::ops::Range::<usize>::from(l.range);
                (K::from_raw(l.kind), &source[range])
            })
            .collect()
    }

    #[test]
    fn a_term_holds_inner_signs_and_slashes() {
        assert_eq!(kinds("web-api+x=1/a.b"), vec![(K::WORD, "web-api+x=1/a.b")]);
        assert_eq!(kinds("-a"), vec![(K::MINUS, "-"), (K::WORD, "a")]);
    }

    #[test]
    fn wildcards_escapes_and_colons_are_pieces() {
        assert_eq!(
            kinds(r"waiting\ un*"),
            vec![
                (K::WORD, "waiting"),
                (K::ESCAPE, r"\ "),
                (K::WORD, "un"),
                (K::STAR, "*")
            ]
        );
        assert_eq!(
            kinds("a:b:c"),
            vec![
                (K::WORD, "a"),
                (K::COLON, ":"),
                (K::WORD, "b"),
                (K::COLON, ":"),
                (K::WORD, "c")
            ]
        );
    }

    #[test]
    fn phrases_escape_quotes_and_run_to_the_end_unclosed() {
        assert_eq!(kinds(r#""a \" b""#), vec![(K::PHRASE_TOKEN, r#""a \" b""#)]);
        assert_eq!(kinds(r#""a b"#), vec![(K::UNCLOSED_PHRASE, r#""a b"#)]);
        assert_eq!(kinds("\"é\\é\""), vec![(K::PHRASE_TOKEN, "\"é\\é\"")]);
    }

    #[test]
    fn a_trailing_backslash_is_an_error() {
        assert_eq!(kinds("a\\"), vec![(K::WORD, "a"), (K::ERROR_TOKEN, "\\")]);
    }

    #[test]
    fn comparison_operators_take_the_longest_match() {
        assert_eq!(kinds(">=1"), vec![(K::GT_EQ, ">="), (K::WORD, "1")]);
    }

    #[test]
    fn numbers_take_exponents_and_duration_units() {
        for yes in [
            "1", "1.5", "1E5", "1E-5", "100ms", "2days", "3µs", "5m", "1.5E-2.5",
        ] {
            assert!(is_number(yes), "{yes}");
        }
        for no in ["", "a1", "1.", "1x", "1E", ".5", "1e5", "10.0.0.0/8"] {
            assert!(!is_number(no), "{no}");
        }
    }
}
