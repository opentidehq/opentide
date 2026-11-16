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
enum Token {
    /// What tree-sitter's `\s` was: the Unicode white space. One character
    /// by the regex, the rest of the run by [`white_space_run`]: a repeated
    /// class with multi-byte members is a repeated group of byte sequences,
    /// which logos' generated code recurses on once per character.
    #[regex(r"[\t\n\x0B\x0C\r \u{85}\u{A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}]", white_space_run)]
    Whitespace,
    #[regex(r"//[^\n]*", allow_greedy = true)]
    Comment,
    /// A word, `$left` included.
    #[regex(r"\$?[A-Za-z_][A-Za-z0-9_]*")]
    Word,
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
    #[regex(r"[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?")]
    Number,
    #[regex(
        r"[0-9]+(\.[0-9]+)?(days?|d|hours?|hrs?|h|minutes?|min|m|seconds?|sec|s|milliseconds?|ms|microseconds?|tick|ticks)"
    )]
    Timespan,
    /// `datetime(2024-01-01 10:00)`: the value is raw text up to `)` on the
    /// same line, as Kusto's lexer reads it.
    #[regex(
        r"(bool|date|datetime|decimal|double|guid|int|int32|int64|long|real|time|timespan)\([^)\r\n]*\)"
    )]
    TypedLiteral,
    /// `"a\"b"`, `'a'`, `@"a""b"`, `@'a''b'`, and the multi-line
    /// ```` ```a``` ```` and `~~~a~~~`, which hold anything but their own
    /// closing fence.
    #[regex(r#""([^"\\]|\\[^\n])*""#)]
    #[regex(r#"'([^'\\]|\\[^\n])*'"#)]
    #[regex(r#"@"([^"]|"")*""#)]
    #[regex(r"@'([^']|'')*'")]
    #[regex(r"```([^`]|`[^`]|``[^`])*```")]
    #[regex(r"~~~([^~]|~[^~]|~~[^~])*~~~")]
    String,
    /// `['Display Name']`, `["c"]`.
    #[regex(r#"\[('([^'\\\r\n]|\\[^\n])*'|"([^"\\\r\n]|\\[^\n])*")\]"#)]
    QuotedIdent,
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
        Token::Word | Token::HyphenWord => word_kind(text).unwrap_or(K::IDENT),
        Token::BangWord => word_kind(text).unwrap_or(K::ERROR_TOKEN),
        Token::HintName => K::HINT_NAME,
        Token::Number => K::NUMBER,
        Token::Timespan => K::TIMESPAN,
        Token::TypedLiteral => K::TYPED_LITERAL,
        Token::String => K::STRING,
        Token::QuotedIdent => K::QUOTED_IDENT,
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
    let lexemes = lex::<Token>(source, |token, text| kind_of(token, text).raw());
    fix_up(source, lexemes)
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
/// after the `with` of `facet`.
const BEFORE_AN_OPERATOR: [K; 4] = [K::PIPE, K::L_PAREN, K::COMMA, K::WITH_KW];

/// What the lexer cannot decide on one token, decided on its neighbours (the
/// tree-sitter lexer knew which tokens its grammar could take here):
///
/// - a hyphen keyword (`parse-where`) that does not start an operator is a
///   subtraction of names (`a - b`), so it is split;
/// - `hint.strategy` is a hint only where an `=` follows, else it is a
///   member access, split in three;
/// - `['k']` after a value (`d['k']`, `d.['k']`) is an index, not a quoted
///   name: split into `[`, the string and `]`.
fn fix_up(source: &str, lexemes: Vec<Lexeme>) -> Vec<Lexeme> {
    let mut out: Vec<Lexeme> = Vec::with_capacity(lexemes.len());
    let mut previous = None;
    for (i, lexeme) in lexemes.iter().enumerate() {
        let kind = K::from_raw(lexeme.kind);
        if kind == K::WHITESPACE || kind == K::COMMENT {
            out.push(*lexeme);
            continue;
        }
        let text = &source[lexeme.range];
        let split_at: Vec<usize> = match kind {
            K::GRANNY_ASC_KW | K::GRANNY_DESC_KW => Vec::new(),
            kind if text.contains('-') && kind.is_word() => {
                if previous.is_some_and(|p| BEFORE_AN_OPERATOR.contains(&p)) {
                    Vec::new()
                } else {
                    text.match_indices('-').map(|(at, _)| at).collect()
                }
            }
            K::HINT_NAME => {
                let next = lexemes[i + 1..]
                    .iter()
                    .find(|l| !matches!(K::from_raw(l.kind), K::WHITESPACE | K::COMMENT));
                if next.is_some_and(|l| K::from_raw(l.kind) == K::EQ) {
                    Vec::new()
                } else {
                    vec![text.find('.').unwrap_or(0)]
                }
            }
            K::QUOTED_IDENT if previous.is_some_and(|p| ENDS_A_VALUE.contains(&p)) => {
                out.extend(split_index(lexeme.range));
                previous = Some(K::R_BRACKET);
                continue;
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

/// `['k']` as `[`, `'k'`, `]`.
fn split_index(range: TextRange) -> [Lexeme; 3] {
    let (start, end) = (range.start(), range.end());
    let one = TextSize::from(1);
    [
        Lexeme {
            kind: K::L_BRACKET.raw(),
            range: TextRange::new(start, start + one),
        },
        Lexeme {
            kind: K::STRING.raw(),
            range: TextRange::new(start + one, end - one),
        },
        Lexeme {
            kind: K::R_BRACKET.raw(),
            range: TextRange::new(end - one, end),
        },
    ]
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
mod tests {
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
        }
        // The fence ends at its first three characters.
        assert_eq!(
            kinds("```a````"),
            vec![(K::STRING, "```a```"), (K::ERROR_TOKEN, "`")]
        );
        // Unclosed: one character is an error, the rest is read again.
        assert_eq!(kinds("\"a")[0], (K::ERROR_TOKEN, "\""));
        assert_eq!(kinds("```a")[0], (K::ERROR_TOKEN, "`"));
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
    fn hints_are_names_unless_an_option() {
        assert_eq!(
            kinds("summarize hint.strategy = shuffle")[1],
            (K::HINT_NAME, "hint.strategy")
        );
        assert_eq!(
            kinds("hint.x == 1")[..3],
            [(K::IDENT, "hint"), (K::DOT, "."), (K::IDENT, "x")]
        );
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

    #[test]
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
