//! The KQL lexer on logos: lossless, context free, then three small fixes
//! that need the token before or after (#1230).
//!
//! The tree-sitter lexer read each word as a keyword only where the grammar
//! took one. This one reads every word as the kind its text names
//! ([`word_kind`]) and leaves it to the parser to take a keyword as a name
//! where a name is wanted (`SyntaxKind::is_word`). What the lexer cannot
//! know it decides from its neighbours, in [`fix_up`].
//!
//! Deliberate changes from the tree-sitter grammar (#1181), as Kusto reads
//! the text: `//` is the only comment (`/* */` is not one), and the
//! ```` ``` ```` and `~~~` multi-line strings are one string token.

use crate::syntax::{SyntaxKind as K, word_kind};
use logos::Logos;
use opentide_parse::{Lexeme, lex};
use rowan::{TextRange, TextSize};

/// What logos reads, before a word is looked up.
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
#[logos(extras = TypedMiss)]
enum Token {
    /// What tree-sitter's `\s` was: the Unicode white space. One character
    /// by the regex, the rest of the run by [`white_space_run`]: a repeated
    /// class with multi-byte members is a repeated group of byte sequences,
    /// which logos' generated code recurses on once per character.
    #[regex(r"[\t\n\x0B\x0C\r \u{85}\u{A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]", white_space_run)]
    Whitespace,
    #[regex(r"//[^\n]*", allow_greedy = true)]
    Comment,
    /// A word, `$left` included; `true` for a typed literal
    /// (`datetime(2024-01-01 10:00)`: a type name, then raw text up to `)` on
    /// the same line, as Kusto's lexer reads it).
    #[regex(r"\$?[A-Za-z_][A-Za-z0-9_]*", typed_literal)]
    Word(bool),
    /// The keywords with a hyphen: read as one token, split by [`fix_up`]
    /// where they are not an operator.
    #[regex(
        r"(project-away|project-rename|project-keep|project-reorder|parse-where|parse-kv|mv-expand|mv-apply|make-series|sample-distinct|top-nested|make-graph|graph-match|graph-shortest-paths|graph-to-table|graph-mark-components|top-hitters|granny-asc|granny-desc)"
    )]
    HyphenWord,
    /// `!has`, `!in~`, ...: a `!` and a word.
    #[regex(r"![a-z_0-9]+~?")]
    BangWord,
    #[regex(r"hint\.[A-Za-z_][A-Za-z0-9_]*")]
    HintName,
    /// A decimal, or a hexadecimal integer (`0x1F`, `0X1f`: an `int` or a
    /// `long`, as Kusto reads it). Kusto.Language also takes a bare `0x`.
    #[regex(r"[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?")]
    #[regex(r"0[xX][0-9A-Fa-f]*")]
    Number,
    #[regex(
        r"[0-9]+(\.[0-9]+)?(days?|d|hours?|hrs?|h|minutes?|min|m|seconds?|sec|s|milliseconds?|ms|microseconds?|tick|ticks)"
    )]
    Timespan,
    /// `"a\"b"`, `'a'`, `@"a""b"`, `@'a''b'`, and the multi-line
    /// ```` ```a``` ```` and `~~~a~~~`, which hold anything but their own
    /// closing fence. Each may be obfuscated, `h` or `H` before it
    /// (`h"secret"`, `H@'x'`, ```` h```x``` ````): one string token, the
    /// prefix included.
    /// `false` when it never closes: the rest of the input is one error
    /// token, so that a broken string costs one scan, not one per character.
    #[token("\"", |lex| quoted(lex, b'"'))]
    #[token("'", |lex| quoted(lex, b'\''))]
    #[token("@\"", |lex| verbatim(lex, b'"'))]
    #[token("@'", |lex| verbatim(lex, b'\''))]
    #[token("```", |lex| fenced(lex, b'`'))]
    #[token("~~~", |lex| fenced(lex, b'~'))]
    #[token("h\"", |lex| quoted(lex, b'"'))]
    #[token("H\"", |lex| quoted(lex, b'"'))]
    #[token("h'", |lex| quoted(lex, b'\''))]
    #[token("H'", |lex| quoted(lex, b'\''))]
    #[token("h@\"", |lex| verbatim(lex, b'"'))]
    #[token("H@\"", |lex| verbatim(lex, b'"'))]
    #[token("h@'", |lex| verbatim(lex, b'\''))]
    #[token("H@'", |lex| verbatim(lex, b'\''))]
    #[token("h```", |lex| fenced(lex, b'`'))]
    #[token("H```", |lex| fenced(lex, b'`'))]
    #[token("h~~~", |lex| fenced(lex, b'~'))]
    #[token("H~~~", |lex| fenced(lex, b'~'))]
    String(bool),
    #[regex(r"==|!=|<>|<=|>=|<|>|=~|!~")]
    CmpOp,
    #[token("in~")]
    InTilde,
    #[token("=")]
    Eq,
    #[token("=>")]
    FatArrow,
    #[token("|")]
    Pipe,
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
    #[token(";")]
    Semicolon,
    #[token(":")]
    Colon,
    #[token(".")]
    Dot,
    #[token("..")]
    DotDot,
    #[token("+")]
    Plus,
    #[token("-")]
    Minus,
    #[token("*")]
    Star,
    #[token("/")]
    Slash,
    #[token("%")]
    Percent,
}

/// The rest of `"..."` or `'...'` after the opening quote: a backslash takes the
/// next character (not a line feed), and the quote ends it. Scanned by a loop:
/// a regex with a repeated group makes logos' generated code recurse per
/// repetition, which a long string turns into a stack overflow. An unclosed
/// string takes the rest of the input (`false`).
fn quoted(lex: &mut logos::Lexer<'_, Token>, quote: u8) -> bool {
    let bytes = lex.remainder().as_bytes();
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        if byte == quote {
            lex.bump(i + 1);
            return true;
        }
        // An escaped character is skipped whole: the bytes of a multi-byte one
        // are never a quote or a backslash. `\` before a line feed ends the string.
        if byte == b'\\' && bytes.get(i + 1).is_some_and(|&b| b != b'\n') {
            i += 2;
        } else if byte == b'\\' {
            break;
        } else {
            i += 1;
        }
    }
    lex.bump(bytes.len());
    false
}

/// The rest of `@"..."` or `@'...'`: a doubled quote is one quote.
fn verbatim(lex: &mut logos::Lexer<'_, Token>, quote: u8) -> bool {
    let bytes = lex.remainder().as_bytes();
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        if byte == quote {
            if bytes.get(i + 1) == Some(&quote) {
                i += 2;
                continue;
            }
            lex.bump(i + 1);
            return true;
        }
        i += 1;
    }
    lex.bump(bytes.len());
    false
}

/// The rest of a multi-line string: up to the first three of the fence's
/// character in a row.
fn fenced(lex: &mut logos::Lexer<'_, Token>, fence: u8) -> bool {
    let bytes = lex.remainder().as_bytes();
    let mut run = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        run = if byte == fence { run + 1 } else { 0 };
        if run == 3 {
            lex.bump(i + 1);
            return true;
        }
    }
    lex.bump(bytes.len());
    false
}

/// The type names that start a typed literal.
const TYPED_LITERAL_TYPES: [&str; 13] = [
    "bool", "date", "datetime", "decimal", "double", "guid", "int", "int32", "int64", "long",
    "real", "time", "timespan",
];

/// Where the scan for a typed literal's `)` last found the end of a line
/// first: a later `datetime(` before it cannot close either, so each line is
/// scanned once, however many unclosed literals it holds.
#[derive(Default)]
struct TypedMiss(usize);

/// After a word: a typed literal when it is a type name and `(`, raw text
/// and `)` follow on the same line (the word and the literal become one
/// token), else a word.
fn typed_literal(lex: &mut logos::Lexer<'_, Token>) -> bool {
    if !TYPED_LITERAL_TYPES.contains(&lex.slice()) || !lex.remainder().starts_with('(') {
        return false;
    }
    let at = lex.span().end;
    if at < lex.extras.0 {
        return false;
    }
    let rest = lex.remainder().as_bytes();
    match rest.iter().position(|&b| matches!(b, b')' | b'\r' | b'\n')) {
        Some(end) if rest[end] == b')' => {
            lex.bump(end + 1);
            true
        }
        Some(end) => {
            lex.extras.0 = at + end;
            false
        }
        None => {
            lex.extras.0 = at + rest.len();
            false
        }
    }
}

/// Whether `c` is white space as the `Whitespace` token reads it (`\s`).
fn is_white_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\u{0B}'
            | '\u{0C}'
            | '\r'
            | ' '
            | '\u{85}'
            | '\u{A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
    )
}

/// The rest of a run of white space after its first character, by a loop.
fn white_space_run(lex: &mut logos::Lexer<'_, Token>) {
    let rest = lex.remainder();
    let end = rest
        .char_indices()
        .find(|&(_, c)| !is_white_space(c))
        .map_or(rest.len(), |(at, _)| at);
    lex.bump(end);
}

/// The kind of a logos token and its text.
fn kind_of(token: Result<Token, ()>, text: &str) -> K {
    let Ok(token) = token else {
        return K::ERROR_TOKEN;
    };
    match token {
        Token::Whitespace => K::WHITESPACE,
        Token::Comment => K::COMMENT,
        Token::Word(true) => K::TYPED_LITERAL,
        Token::Word(false) | Token::HyphenWord => word_kind(text).unwrap_or(K::IDENT),
        Token::BangWord => word_kind(text).unwrap_or(K::ERROR_TOKEN),
        Token::HintName => K::HINT_NAME,
        Token::Number => K::NUMBER,
        Token::Timespan => K::TIMESPAN,
        Token::String(true) => K::STRING,
        Token::String(false) => K::ERROR_TOKEN,
        Token::CmpOp => K::CMP_OP,
        Token::InTilde => K::SET_OP,
        Token::Eq => K::EQ,
        Token::FatArrow => K::FAT_ARROW,
        Token::Pipe => K::PIPE,
        Token::LParen => K::L_PAREN,
        Token::RParen => K::R_PAREN,
        Token::LBracket => K::L_BRACKET,
        Token::RBracket => K::R_BRACKET,
        Token::LBrace => K::L_BRACE,
        Token::RBrace => K::R_BRACE,
        Token::Comma => K::COMMA,
        Token::Semicolon => K::SEMICOLON,
        Token::Colon => K::COLON,
        Token::Dot => K::DOT,
        Token::DotDot => K::DOT_DOT,
        Token::Plus => K::PLUS,
        Token::Minus => K::MINUS,
        Token::Star => K::STAR,
        Token::Slash => K::SLASH,
        Token::Percent => K::PERCENT,
    }
}

/// Lexes `source`: every byte is in one lexeme (whitespace and comments
/// are trivia, a character no token takes is an `ERROR_TOKEN`).
pub(crate) fn lex_kql(source: &str) -> Vec<Lexeme> {
    lex_kql_indexing(source, &[])
}

/// [`lex_kql`], reading the brackets that open at `index_at` (sorted) as an index
/// (`[`, a string, `]`), never as a quoted name: where the parser found a
/// quoted name right after an expression, which the old grammar read as
/// `step['x']`. A hyphen keyword that starts at one of `index_at` is split
/// into names and a minus: where the parser found it starting an expression
/// (`count(project-away)`), as the old grammar read it.
pub(crate) fn lex_kql_indexing(source: &str, index_at: &[TextSize]) -> Vec<Lexeme> {
    let lexemes = lex::<Token>(source, |token, text| kind_of(token, text).raw());
    fix_up(source, lexemes, index_at)
}

/// The kinds that end a primary expression: a `[` after one indexes it.
const ENDS_A_VALUE: [K; 6] = [
    K::IDENT,
    K::R_PAREN,
    K::R_BRACKET,
    K::STRING,
    K::QUOTED_IDENT,
    K::DOT,
];

/// The kinds a hyphen keyword may follow: an operator starts after a pipe,
/// after the `(` of a sub-pipeline, after the comma of `top-nested`, and
/// after the `with` of `facet` (only there: `| with a-b` is an unknown
/// operator `with` and a subtraction).
const BEFORE_AN_OPERATOR: [K; 3] = [K::PIPE, K::L_PAREN, K::COMMA];

/// What the lexer cannot decide on one token, decided on its neighbours (the
/// tree-sitter lexer knew which tokens its grammar could take here):
///
/// - a hyphen keyword (`parse-where`) that does not start an operator is a
///   subtraction of names (`a - b`), so it is split; after a `(` or a `,`
///   it may start one, unless the parser said it starts an expression;
/// - `['k']` after a value (`d['k']`, `d.['k']`) is an index, not a quoted
///   name: split into `[`, the string and `]`.
fn fix_up(source: &str, lexemes: Vec<Lexeme>, index_at: &[TextSize]) -> Vec<Lexeme> {
    let mut out: Vec<Lexeme> = Vec::with_capacity(lexemes.len());
    let mut previous = None;
    // Since the last pipe, a `facet` came: its `with` may start an operator.
    let mut in_facet = false;
    let mut i = 0;
    while let Some(lexeme) = lexemes.get(i) {
        i += 1;
        let kind = K::from_raw(lexeme.kind);
        if kind == K::WHITESPACE || kind == K::COMMENT {
            out.push(*lexeme);
            continue;
        }
        if kind == K::L_BRACKET
            && !previous.is_some_and(|p| ENDS_A_VALUE.contains(&p))
            && index_at.binary_search(&lexeme.range.start()).is_err()
            && let Some(range) = quoted_name(source, &lexemes[i - 1..])
        {
            // `['Display Name']`: three tokens that touch, a name.
            out.push(Lexeme {
                kind: K::QUOTED_IDENT.raw(),
                range,
            });
            previous = Some(K::QUOTED_IDENT);
            i += 2;
            continue;
        }
        match kind {
            K::PIPE => in_facet = false,
            K::FACET_KW => in_facet = true,
            _ => {}
        }
        let text = &source[lexeme.range];
        let split_at: Vec<usize> = match kind {
            K::GRANNY_ASC_KW | K::GRANNY_DESC_KW => Vec::new(),
            kind if text.contains('-') && kind.is_word() => {
                let facet_with = previous == Some(K::WITH_KW) && in_facet;
                // Where the parser wanted an expression (`count(project-away)`):
                // names and a minus, whatever came before.
                let in_expression = index_at.binary_search(&lexeme.range.start()).is_ok();
                if !in_expression
                    && (facet_with || previous.is_some_and(|p| BEFORE_AN_OPERATOR.contains(&p)))
                {
                    Vec::new()
                } else {
                    text.match_indices('-').map(|(at, _)| at).collect()
                }
            }
            _ => Vec::new(),
        };
        if split_at.is_empty() {
            out.push(*lexeme);
            previous = Some(kind);
            continue;
        }
        previous = Some(split_words(lexeme.range, text, &split_at, &mut out));
    }
    out
}

/// The range of `['Display Name']` or `["c"]` when `lexemes` starts with its
/// three touching tokens: `[`, a quoted string with no line break in it (not
/// a verbatim or multi-line one), `]`.
fn quoted_name(source: &str, lexemes: &[Lexeme]) -> Option<TextRange> {
    let [open, string, close, ..] = lexemes else {
        return None;
    };
    let text = &source[string.range];
    let plain = K::from_raw(string.kind) == K::STRING
        && text.starts_with(['"', '\''])
        && !text.contains(['\r', '\n']);
    let touching =
        open.range.end() == string.range.start() && string.range.end() == close.range.start();
    (plain && touching && K::from_raw(close.kind) == K::R_BRACKET)
        .then(|| TextRange::new(open.range.start(), close.range.end()))
}

/// Cuts the word at `range` at the separators `at` (byte offsets of a `-` or
/// a `.` in `text`): each piece is a word (a keyword or a name), each
/// separator a `-` or a `.`. Returns the kind of the last lexeme.
fn split_words(range: TextRange, text: &str, at: &[usize], out: &mut Vec<Lexeme>) -> K {
    let base = range.start();
    let to = |n: usize| base + TextSize::try_from(n).unwrap_or_default();
    let mut from = 0;
    let mut last = K::IDENT;
    for &cut in at.iter().chain(std::iter::once(&text.len())) {
        if cut > from {
            last = word_kind(&text[from..cut]).unwrap_or(K::IDENT);
            out.push(Lexeme {
                kind: last.raw(),
                range: TextRange::new(to(from), to(cut)),
            });
        }
        if cut < text.len() {
            last = if text.as_bytes()[cut] == b'.' {
                K::DOT
            } else {
                K::MINUS
            };
            out.push(Lexeme {
                kind: last.raw(),
                range: TextRange::new(to(cut), to(cut + 1)),
            });
        }
        from = cut + 1;
    }
    last
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::syntax::{OPERATOR_WORDS, TEXTS};

    fn kinds(source: &str) -> Vec<(K, &str)> {
        lex_kql(source)
            .into_iter()
            .filter(|l| !matches!(K::from_raw(l.kind), K::WHITESPACE))
            .map(|l| (K::from_raw(l.kind), &source[l.range]))
            .collect()
    }

    #[test]
    fn every_word_and_symbol_lexes_as_its_kind() {
        for (text, kind) in TEXTS {
            // Hyphen keywords are operators after a pipe.
            let source = format!("| {text}");
            assert_eq!(kinds(&source)[1], (*kind, *text), "{text}");
        }
        for (text, kind) in OPERATOR_WORDS {
            assert_eq!(kinds(text), vec![(*kind, *text)], "{text}");
        }
    }

    #[test]
    fn names_numbers_and_timespans() {
        assert_eq!(
            kinds("$left Foo_1 1 1.5e3 5m 1.5h 10min 3dx"),
            vec![
                (K::IDENT, "$left"),
                (K::IDENT, "Foo_1"),
                (K::NUMBER, "1"),
                (K::NUMBER, "1.5e3"),
                (K::TIMESPAN, "5m"),
                (K::TIMESPAN, "1.5h"),
                (K::TIMESPAN, "10min"),
                (K::TIMESPAN, "3d"),
                (K::IDENT, "x"),
            ]
        );
        assert_eq!(
            kinds("0x1F 0X1f 0xFFFFFFFFFFFFFFFF 0x 0xg"),
            vec![
                (K::NUMBER, "0x1F"),
                (K::NUMBER, "0X1f"),
                (K::NUMBER, "0xFFFFFFFFFFFFFFFF"),
                (K::NUMBER, "0x"),
                (K::NUMBER, "0x"),
                (K::IDENT, "g"),
            ]
        );
        assert_eq!(
            kinds("1..3 2.x"),
            vec![
                (K::NUMBER, "1"),
                (K::DOT_DOT, ".."),
                (K::NUMBER, "3"),
                (K::NUMBER, "2"),
                (K::DOT, "."),
                (K::IDENT, "x"),
            ]
        );
    }

    #[test]
    fn strings_in_every_form() {
        for text in [
            r#""a\"b""#,
            r#"'a\'b'"#,
            r#"@"a""b""#,
            r#"@'a''b'"#,
            "```a\n\"b\" `c` ``d```",
            "~~~a\n~b~~c~~~",
        ] {
            assert_eq!(kinds(text), vec![(K::STRING, text)], "{text}");
            // Obfuscated: `h` or `H` before any of them is the same string.
            for prefix in ["h", "H"] {
                let obfuscated = format!("{prefix}{text}");
                assert_eq!(
                    kinds(&obfuscated),
                    vec![(K::STRING, obfuscated.as_str())],
                    "{obfuscated}"
                );
            }
        }
        // Only right before the quote: `h "a"` is a name and a string, and a
        // longer word before a quote stays a word.
        assert_eq!(
            kinds(r#"h "a" ah"b""#),
            vec![
                (K::IDENT, "h"),
                (K::STRING, r#""a""#),
                (K::IDENT, "ah"),
                (K::STRING, r#""b""#),
            ]
        );
        assert_eq!(kinds("h'a"), vec![(K::ERROR_TOKEN, "h'a")]);
        // The fence ends at its first three characters.
        assert_eq!(
            kinds("```a````"),
            vec![(K::STRING, "```a```"), (K::ERROR_TOKEN, "`")]
        );
        // Unclosed: the rest of the input is one error token.
        assert_eq!(
            kinds("x \"a\nb"),
            vec![(K::IDENT, "x"), (K::ERROR_TOKEN, "\"a\nb")]
        );
        assert_eq!(kinds("```a`` b"), vec![(K::ERROR_TOKEN, "```a`` b")]);
        assert_eq!(kinds("@'a''"), vec![(K::ERROR_TOKEN, "@'a''")]);
    }

    #[test]
    fn only_slash_slash_starts_a_comment() {
        assert_eq!(kinds("a // b */\nc")[1], (K::COMMENT, "// b */"));
        let got: Vec<K> = kinds("a /* b */ c").iter().map(|t| t.0).collect();
        assert_eq!(
            got,
            [
                K::IDENT,
                K::SLASH,
                K::STAR,
                K::IDENT,
                K::STAR,
                K::SLASH,
                K::IDENT
            ]
        );
    }

    #[test]
    fn typed_literals_and_the_names_they_fall_back_to() {
        assert_eq!(kinds("datetime(2024-01-01 10:00)")[0].0, K::TYPED_LITERAL);
        assert_eq!(kinds("long(null)")[0].0, K::TYPED_LITERAL);
        // No `)` on the line: a name and a parenthesis.
        assert_eq!(
            kinds("int(1\n)"),
            vec![
                (K::IDENT, "int"),
                (K::L_PAREN, "("),
                (K::NUMBER, "1"),
                (K::R_PAREN, ")")
            ]
        );
        assert_eq!(kinds("time_x(1)")[0], (K::IDENT, "time_x"));
    }

    #[test]
    fn operators_made_of_words_and_bangs() {
        let got: Vec<K> = kinds("a !has b !in~ (c) !~ d !x in~")
            .iter()
            .map(|t| t.0)
            .collect();
        assert_eq!(
            got,
            [
                K::IDENT,
                K::CMP_OP,
                K::IDENT,
                K::SET_OP,
                K::L_PAREN,
                K::IDENT,
                K::R_PAREN,
                K::CMP_OP,
                K::IDENT,
                K::ERROR_TOKEN,
                K::SET_OP
            ]
        );
        assert_eq!(kinds("a==b<>c<=d=~e=>f")[1].0, K::CMP_OP);
    }

    #[test]
    fn a_hyphen_keyword_is_an_operator_only_where_one_starts() {
        assert_eq!(
            kinds("T | project-away a")[2],
            (K::PROJECT_AWAY_KW, "project-away")
        );
        assert_eq!(
            kinds("T | take 1 | parse-kv x")[5],
            (K::PARSE_KV_KW, "parse-kv")
        );
        let got: Vec<K> = kinds("x = parse-where").iter().map(|t| t.0).collect();
        assert_eq!(got, [K::IDENT, K::EQ, K::PARSE_KW, K::MINUS, K::WHERE_KW]);
        assert_eq!(kinds("a graph-shortest-paths").len(), 6);
        assert_eq!(kinds("a granny-asc")[1], (K::GRANNY_ASC_KW, "granny-asc"));
    }

    #[test]
    fn a_hint_is_one_token_wherever_it_stands() {
        // As tree-sitter lexed it: `hint.x` is a hint name, so a member `x` of
        // a column `hint` is a syntax error there (and here).
        assert_eq!(
            kinds("summarize hint.strategy = shuffle")[1],
            (K::HINT_NAME, "hint.strategy")
        );
        assert_eq!(kinds("hint.x == 1")[0], (K::HINT_NAME, "hint.x"));
        assert_eq!(kinds("hint .x")[0], (K::IDENT, "hint"));
    }

    #[test]
    fn a_bracketed_string_is_a_name_or_an_index() {
        assert_eq!(kinds("project ['a b']")[1], (K::QUOTED_IDENT, "['a b']"));
        assert_eq!(kinds("x, [\"a\"]")[2], (K::QUOTED_IDENT, "[\"a\"]"));
        let got: Vec<K> = kinds("d['k']").iter().map(|t| t.0).collect();
        assert_eq!(got, [K::IDENT, K::L_BRACKET, K::STRING, K::R_BRACKET]);
        let got: Vec<K> = kinds("d.[\"a.b\"]").iter().map(|t| t.0).collect();
        assert_eq!(
            got,
            [K::IDENT, K::DOT, K::L_BRACKET, K::STRING, K::R_BRACKET]
        );
        assert_eq!(kinds("a['x']['y']").len(), 7);
    }

    /// The lexemes feed the toolkit and come back as a lossless tree of this
    /// language's kinds.
    #[test]
    fn the_lexemes_build_a_lossless_tree() {
        use crate::syntax::{SyntaxNode, SyntaxToken};
        use opentide_parse::{Grammar, Input, Parser, TokenSet, build};
        let source = "T | where a == 1 // c\n| take 5";
        let grammar = Grammar {
            eof: K::EOF.raw(),
            error: K::ERROR.raw(),
            trivia: TokenSet::new(&[K::WHITESPACE.raw(), K::COMMENT.raw()]),
            max_depth: 64,
        };
        let input = Input::new(source, lex_kql(source), grammar);
        let mut p = Parser::new(&input);
        let root = p.start();
        while !p.at_eof() {
            p.bump();
        }
        root.complete(&mut p, K::SOURCE_FILE.raw());
        let tree = SyntaxNode::new_root(build(&input, p.finish()).green);
        assert_eq!(tree.kind(), K::SOURCE_FILE);
        assert_eq!(tree.to_string(), source);
        let comment = tree
            .descendants_with_tokens()
            .filter_map(|e| e.into_token())
            .find(|t: &SyntaxToken| t.kind() == K::COMMENT);
        assert_eq!(
            comment.map(|t| t.text().to_owned()),
            Some("// c".to_owned())
        );
    }

    /// Found by review (#1314): a run of multi-byte white space (`\u{3000}`,
    /// `\u{A0}`) aborted on a 1 MB stack: the repeated class recursed once
    /// per character in logos' generated code. A run is one token whatever
    /// its length or mix, and `\s` is still the set it was.
    #[test]
    fn a_long_run_of_white_space_is_one_token_on_a_small_stack() {
        for unit in ["\u{3000}", "\u{A0}", " \u{2028}\t", "\u{205F}\r\n"] {
            let source = unit.repeat(1_000_000);
            let lexemes = std::thread::Builder::new()
                .stack_size(1 << 20)
                .spawn(move || lex_kql(&source).len())
                .expect("spawn")
                .join()
                .expect("the lexer overflowed or panicked");
            assert_eq!(lexemes, 1, "{unit:?}");
        }
        for c in (0..=0x3000).filter_map(char::from_u32) {
            // `\s` is Unicode's White_Space, which is what `is_whitespace` reads.
            let white = c.is_whitespace();
            let source = format!("a{c}b");
            let kinds: Vec<K> = lex_kql(&source)
                .iter()
                .map(|l| K::from_raw(l.kind))
                .collect();
            assert_eq!(kinds.get(1) == Some(&K::WHITESPACE), white, "{c:?}");
        }
    }

    #[test]
    fn unicode_white_space_is_trivia_and_other_characters_are_errors() {
        let got: Vec<K> = lex_kql("a\u{A0}\u{3000}b é")
            .iter()
            .map(|l| K::from_raw(l.kind))
            .collect();
        assert_eq!(
            got,
            [
                K::IDENT,
                K::WHITESPACE,
                K::IDENT,
                K::WHITESPACE,
                K::ERROR_TOKEN
            ]
        );
    }
}
