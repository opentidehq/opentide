//! The EQL lexer: logos for the words and the fixed tokens, hand scanners (logos callbacks) for
//! what the tree-sitter grammar spelled as a regex a pre-lexed stream cannot backtrack over:
//! numbers, the five string forms, quoted names, `[0]` indexes and comments.
//!
//! Every scanner reads what tree-sitter's lexer read, which is the longest match of its regex,
//! and where a scan fails the first character is a single token of its own (`"` of an unclosed
//! string is [`K::ERROR_TOKEN`], and lexing goes on after it). A block comment is a lexer mode:
//! [`es_comment_end`] ends it where Elasticsearch's lexer does, which nests, so the source needs
//! no masking. Nothing is skipped: the lexemes tile the source, whitespace and comments
//! included. Words are not keywords here: `and`, `where`, `in~` and the rest are
//! [`K::WORD`] and [`K::TILDE_WORD`] and the parser re-kinds them.

use crate::syntax::SyntaxKind as K;
use logos::{Lexer, Logos};
use opentide_parse::Lexeme;

/// The simulation of a nested comment may do this many steps for each byte of the source.
const FUEL_PER_BYTE: usize = 6;

/// Where a scan already failed: every later start of the same kind fails too (the scan from
/// there walks the same characters), so it is not repeated, which would make a source of
/// unterminated openers quadratic.
#[derive(Clone, Copy, Debug, Default)]
struct Memo {
    /// No `*/` follows a `/*` from here on.
    no_block_end: bool,
    /// What is left of the simulation's budget, once it is first needed (`None` before).
    fuel: Option<usize>,
    /// No closing `"` follows a `"` before this offset (the end of the line).
    double: usize,
    /// No closing `'` follows a `'` before this offset.
    single: usize,
}

#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
#[logos(extras = Memo)]
enum Token {
    #[regex(r"[ \t\n\x0b\x0c\r]+")]
    Whitespace,
    #[regex(r"[A-Za-z_@][A-Za-z0-9_]*")]
    Word,
    #[regex(r"[A-Za-z][A-Za-z0-9_]*~")]
    TildeWord,
    #[token("|")]
    Pipe,
    #[token("=")]
    Eq,
    #[token("==")]
    EqEq,
    #[token("!=")]
    NotEq,
    #[token("<")]
    Lt,
    #[token("<=")]
    LtEq,
    #[token(">")]
    Gt,
    #[token(">=")]
    GtEq,
    #[token("+")]
    Plus,
    #[token("-")]
    Minus,
    #[token("*")]
    Star,
    #[token("%")]
    Percent,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("]")]
    RBrack,
    #[token("![")]
    BangLBrack,
    #[token(",")]
    Comma,
    #[token(":")]
    Colon,
    /// A token a scanner cut: a number, a string, a name, an index, a comment.
    #[regex(r"[0-9]", number)]
    #[token(".", dot)]
    #[token("\"", double_quote)]
    #[token("'", single_quote)]
    #[token("?", question)]
    #[token("`", quoted_name)]
    #[token("[", bracket)]
    #[token("/", slash)]
    Scanned(K),
    /// Any other character: one error token.
    #[regex(r"(?s).", priority = 1)]
    Other,
}

impl Token {
    fn kind(self) -> K {
        match self {
            Self::Whitespace => K::WHITESPACE,
            Self::Word => K::WORD,
            Self::TildeWord => K::TILDE_WORD,
            Self::Pipe => K::PIPE,
            Self::Eq => K::EQ,
            Self::EqEq => K::EQ_EQ,
            Self::NotEq => K::NOT_EQ,
            Self::Lt => K::LT,
            Self::LtEq => K::LT_EQ,
            Self::Gt => K::GT,
            Self::GtEq => K::GT_EQ,
            Self::Plus => K::PLUS,
            Self::Minus => K::MINUS,
            Self::Star => K::STAR,
            Self::Percent => K::PERCENT,
            Self::LParen => K::L_PAREN,
            Self::RParen => K::R_PAREN,
            Self::RBrack => K::R_BRACK,
            Self::BangLBrack => K::BANG_L_BRACK,
            Self::Comma => K::COMMA,
            Self::Colon => K::COLON,
            Self::Scanned(kind) => kind,
            Self::Other => K::ERROR_TOKEN,
        }
    }
}

// ---- Characters ----------------------------------------------------------------------------

/// The whitespace of the grammar: `\t` to `\r`, and the space.
fn is_space(b: u8) -> bool {
    matches!(b, b'\t'..=b'\r' | b' ')
}

fn skip(bytes: &[u8], mut i: usize, keep: impl Fn(u8) -> bool) -> usize {
    while bytes.get(i).is_some_and(|&b| keep(b)) {
        i += 1;
    }
    i
}

/// The offset of the next `\r` or `\n` at or after `i`, or the length of `bytes`.
fn line_end(bytes: &[u8], i: usize) -> usize {
    skip(bytes, i, |b| b != b'\r' && b != b'\n')
}

/// Extends the token to `end` (an absolute offset into the lexer's source).
fn extend(lex: &mut Lexer<'_, Token>, end: usize) {
    let have = lex.span().end;
    lex.bump(end.saturating_sub(have));
}

// ---- Numbers -------------------------------------------------------------------------------

/// The end of the exponent `[eE][+-]?[0-9]+` at `i`, or `i` when there is none.
fn exponent(bytes: &[u8], i: usize) -> usize {
    if !matches!(bytes.get(i), Some(b'e' | b'E')) {
        return i;
    }
    let sign = i + 1 + usize::from(matches!(bytes.get(i + 1), Some(b'+' | b'-')));
    let end = skip(bytes, sign, |b| b.is_ascii_digit());
    if end > sign { end } else { i }
}

/// `[0-9]+`, `[0-9]+\.[0-9]*(exp)?` and `[0-9]+exp`: a digit starts it.
fn number(lex: &mut Lexer<'_, Token>) -> K {
    let bytes = lex.source().as_bytes();
    let mut end = skip(bytes, lex.span().end, |b| b.is_ascii_digit());
    if bytes.get(end) == Some(&b'.') {
        end = exponent(bytes, skip(bytes, end + 1, |b| b.is_ascii_digit()));
    } else {
        end = exponent(bytes, end);
    }
    extend(lex, end);
    K::NUMBER_TOKEN
}

/// `.` is a delimiter, and `\.[0-9]+(exp)?` a number.
fn dot(lex: &mut Lexer<'_, Token>) -> K {
    let bytes = lex.source().as_bytes();
    let digits = skip(bytes, lex.span().end, |b| b.is_ascii_digit());
    if digits == lex.span().end {
        return K::DOT;
    }
    extend(lex, exponent(bytes, digits));
    K::NUMBER_TOKEN
}

// ---- Strings and names ---------------------------------------------------------------------

/// `"""` to the first `"""` on the line, and up to two more `"`; else `"` ... `"`.
fn double_quote(lex: &mut Lexer<'_, Token>) -> K {
    let start = lex.span().start;
    let bytes = lex.source().as_bytes();
    if bytes[start..].starts_with(b"\"\"\"")
        && let Some(end) = triple_end(bytes, start + 3)
    {
        extend(lex, end);
        return K::STRING_TOKEN;
    }
    if start < lex.extras.double {
        return K::ERROR_TOKEN;
    }
    match quoted_end(bytes, start + 1, b'"') {
        Ok(end) => {
            extend(lex, end);
            K::STRING_TOKEN
        }
        Err(failed) => {
            lex.extras.double = failed;
            K::ERROR_TOKEN
        }
    }
}

/// `'` ... `'`.
fn single_quote(lex: &mut Lexer<'_, Token>) -> K {
    let start = lex.span().start;
    let bytes = lex.source().as_bytes();
    if start < lex.extras.single {
        return K::ERROR_TOKEN;
    }
    match quoted_end(bytes, start + 1, b'\'') {
        Ok(end) => {
            extend(lex, end);
            K::STRING_TOKEN
        }
        Err(failed) => {
            lex.extras.single = failed;
            K::ERROR_TOKEN
        }
    }
}

/// The end of a `"` or `'` string whose body starts at `i`: a backslash takes any character
/// but a line feed, and a raw carriage return or line feed ends the line. A failed scan gives
/// the offset it failed at: no start before it succeeds either.
fn quoted_end(bytes: &[u8], mut i: usize, quote: u8) -> Result<usize, usize> {
    loop {
        match bytes.get(i) {
            None => return Err(bytes.len()),
            Some(b'\\') => match bytes.get(i + 1) {
                Some(b'\n') | None => return Err(i),
                Some(_) => i += 2,
            },
            Some(b'\r' | b'\n') => return Err(i),
            Some(&b) if b == quote => return Ok(i + 1),
            Some(_) => i += 1,
        }
    }
}

/// The end of a `"""` string whose body starts at `i`. A run of quotes is content when a
/// character that is not a quote or a line break follows it and it is shorter than three; a
/// run of three or more closes the string, and up to two of its quotes after the closing
/// `"""` belong to it.
fn triple_end(bytes: &[u8], mut i: usize) -> Option<usize> {
    loop {
        match *bytes.get(i)? {
            b'\r' | b'\n' => return None,
            b'"' => {
                // Five quotes are all that matter: a longer run is not counted (that would
                // make a run of quotes quadratic).
                let run = bytes[i..]
                    .iter()
                    .take(5)
                    .take_while(|&&b| b == b'"')
                    .count();
                if run >= 3 {
                    return Some(i + run.min(5));
                }
                match bytes.get(i + run) {
                    None | Some(b'\r' | b'\n') => return None,
                    // The character after the run is content too (`"X` or `""X`).
                    Some(_) => i += run + 1,
                }
            }
            _ => i += 1,
        }
    }
}

/// `?"` and `?'` open a raw string (a backslash is a character, `\"` too); a lone `?` is the
/// optional-field marker. The string ends at the first quote not after a backslash, else at
/// the last quote of the line (a `\"` may close it too).
fn question(lex: &mut Lexer<'_, Token>) -> K {
    let start = lex.span().start;
    let bytes = lex.source().as_bytes();
    let Some(&quote @ (b'"' | b'\'')) = bytes.get(start + 1) else {
        return K::QUESTION;
    };
    let mut last = None;
    let mut i = start + 2;
    while let Some(&b) = bytes.get(i) {
        if b == b'\r' || b == b'\n' {
            break;
        }
        if b == quote {
            last = Some(i + 1);
            if bytes[i - 1] != b'\\' {
                break;
            }
        }
        i += 1;
    }
    match last {
        Some(end) => {
            extend(lex, end);
            K::STRING_TOKEN
        }
        None => K::QUESTION,
    }
}

/// A name in backticks: a doubled backtick is one inside. Of a run of backticks, an odd run
/// ends the name at its end, and an even one is all content, unless nothing closes later, when
/// the name ends one backtick before the run's end.
fn quoted_name(lex: &mut Lexer<'_, Token>) -> K {
    let bytes = lex.source().as_bytes();
    let mut i = lex.span().end;
    let mut fallback = None;
    loop {
        match bytes.get(i) {
            None => break,
            Some(b'`') => {
                let end = skip(bytes, i, |b| b == b'`');
                if (end - i) % 2 == 1 {
                    extend(lex, end);
                    return K::QUOTED_IDENT_TOKEN;
                }
                fallback = Some(end - 1);
                i = end;
            }
            Some(_) => i += 1,
        }
    }
    match fallback {
        Some(end) => {
            extend(lex, end);
            K::QUOTED_IDENT_TOKEN
        }
        None => K::ERROR_TOKEN,
    }
}

// ---- Indexes and comments ------------------------------------------------------------------

/// `[` (`\s*[0-9]+`)+ `\s*]` is an index token; else the bracket opens an event.
fn bracket(lex: &mut Lexer<'_, Token>) -> K {
    let bytes = lex.source().as_bytes();
    let mut i = lex.span().end;
    let mut numbers = 0;
    loop {
        i = skip(bytes, i, is_space);
        let end = skip(bytes, i, |b| b.is_ascii_digit());
        if end == i {
            break;
        }
        numbers += 1;
        i = end;
    }
    if numbers > 0 && bytes.get(i) == Some(&b']') {
        extend(lex, i + 1);
        return K::INDEX_TOKEN;
    }
    K::L_BRACK
}

/// `//` to the end of the line, `/* ... */` as Elasticsearch ends it, or the division.
fn slash(lex: &mut Lexer<'_, Token>) -> K {
    let start = lex.span().start;
    let bytes = lex.source().as_bytes();
    match bytes.get(start + 1) {
        Some(b'/') => {
            extend(lex, line_end(bytes, start));
            K::LINE_COMMENT
        }
        Some(b'*') if !lex.extras.no_block_end => {
            let Some(first) = find_block_end(bytes, start + 2) else {
                lex.extras.no_block_end = true;
                return K::SLASH;
            };
            // Without an inner `/*` the first `*/` ends it. Otherwise where Elasticsearch ends
            // it; where it reads no comment at all, the first `*/` (the grammar's reading,
            // which the analysis reports).
            let end = if find_open(&bytes[start + 2..first - 1]) {
                let fuel = lex
                    .extras
                    .fuel
                    .get_or_insert(4_096 + FUEL_PER_BYTE * bytes.len());
                es_comment_end(bytes, start, fuel).unwrap_or(first)
            } else {
                first
            };
            extend(lex, end);
            K::BLOCK_COMMENT
        }
        _ => K::SLASH,
    }
}

/// Whether `bytes` has a `/*`.
fn find_open(bytes: &[u8]) -> bool {
    bytes.windows(2).any(|w| w == b"/*")
}

/// The end of the first `*/` at or after `from`.
fn find_block_end(bytes: &[u8], from: usize) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(2)
        .position(|w| w == b"*/")
        .map(|n| from + n + 2)
}

/// Where Elasticsearch's lexer ends the block comment that opens at `start`.
///
/// The rule is `'/*' (BRACKETED_COMMENT | .)*? '*/'`: an inner `/*` may open a nested comment or
/// be plain text, and an inner `*/` closes the innermost level. ANTLR explores the
/// alternatives in order (close, nest, any character), drops lower-priority paths once one
/// path finishes the token, and keeps the longest finish. This simulates that, one character
/// at a time, over `(depth, phase)` states. `None` means no comment is lexed. A comment with
/// too many open paths, or one that runs the `fuel` of the whole source out (the work is a
/// state per character: a source of many openers would otherwise rescan the rest of itself for
/// each), is left to the grammar (the first `*/`).
pub(crate) fn es_comment_end(bytes: &[u8], start: usize, fuel: &mut usize) -> Option<usize> {
    const NORMAL: u8 = 0;
    const STAR: u8 = 1;
    const SLASH: u8 = 2;
    const MAX_STATES: usize = 96;
    let mut states: Vec<(u32, u8)> = vec![(1, NORMAL)];
    let mut best = None;
    let mut pos = start + 2;
    while !states.is_empty() && pos < bytes.len() {
        let c = bytes[pos];
        let Some(left) = fuel.checked_sub(states.len()) else {
            *fuel = 0;
            return find_block_end(bytes, start + 2);
        };
        *fuel = left;
        let mut next: Vec<(u32, u8)> = Vec::with_capacity(states.len() + 2);
        for &(depth, phase) in &states {
            match phase {
                NORMAL => {
                    if c == b'*' {
                        push((depth, STAR), &mut next);
                    }
                    if c == b'/' {
                        push((depth, SLASH), &mut next);
                    }
                    push((depth, NORMAL), &mut next);
                }
                STAR if c == b'/' => {
                    if depth == 1 {
                        best = Some(pos + 1);
                        break;
                    }
                    push((depth - 1, NORMAL), &mut next);
                }
                SLASH if c == b'*' => push((depth + 1, NORMAL), &mut next),
                _ => {}
            }
        }
        if next.len() > MAX_STATES {
            // Pathological input: the grammar's reading.
            return find_block_end(bytes, start + 2);
        }
        states = next;
        pos += 1;
    }
    best
}

/// Adds a state unless an earlier (higher-priority) path already holds it.
fn push(state: (u32, u8), next: &mut Vec<(u32, u8)>) {
    if !next.contains(&state) {
        next.push(state);
    }
}

// ---- The lexer -----------------------------------------------------------------------------

/// Lexes `source`: every byte is in exactly one lexeme.
pub(crate) fn lex(source: &str) -> Vec<Lexeme> {
    opentide_parse::lex::<Token>(source, |token, _| match token {
        Ok(token) => token.kind().raw(),
        Err(()) => K::ERROR_TOKEN.raw(),
    })
}
