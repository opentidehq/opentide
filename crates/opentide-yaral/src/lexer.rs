//! The YARA-L lexer: logos for the tokens, and hand-written scanners for the
//! ones that repeat (strings, regular expressions, comments).
//!
//! The tree-sitter grammar lexed by what the parser could accept next; the
//! pre-lexed token stream has no parser to ask, so three things are decided
//! here:
//!
//! - every reserved word is read as its keyword in any case (`aNd`), and
//!   `every`, `first`, `cross`, `join` and `graph_*`, which are keywords only
//!   where the grammar takes them, as names ([`K::IDENT`]);
//! - a `/` starts a regular expression whenever one is there to read (longest
//!   match, as tree-sitter's lexer chose between `/` and a regex), else it is
//!   the division operator;
//! - a path's dot and bracket have no blank before them ([`K::ACCESS_DOT`],
//!   [`K::INDEX_L_BRACK`]) and follow a variable, a name or `]`; the word
//!   right after an access dot is a [`K::FIELD_NAME`], whatever it is spelled
//!   like (`network.dhcp.options`).
//!
//! The scanners are loops, not logos regexes: a regex with a repeated group
//! over alternatives makes logos' generated code recurse once per repetition,
//! and a string of a million escapes would overflow the stack.

use crate::syntax::SyntaxKind as K;
use logos::Logos;
use opentide_parse::Lexeme;

/// The tokens of YARA-L; a word that is not reserved is [`Tok::Word`].
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    #[regex(
        r"[ \t\n\x0B\x0C\r\u{85}\u{a0}\u{1680}\u{2000}-\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}]+"
    )]
    Whitespace,
    #[token("//", line_comment)]
    LineComment,
    #[token("/*", block_comment)]
    BlockComment,
    #[token("/", slash)]
    Slash(Slash),
    #[token("\"", string)]
    String,
    #[token("`", raw_string)]
    RawString,
    #[regex(r"[A-Za-z_][A-Za-z0-9_]*")]
    Word,
    #[token("rule", |_| K::RULE_KW, ignore(case))]
    #[token("meta", |_| K::META_KW, ignore(case))]
    #[token("setup", |_| K::SETUP_KW, ignore(case))]
    #[token("events", |_| K::EVENTS_KW, ignore(case))]
    #[token("match", |_| K::MATCH_KW, ignore(case))]
    #[token("outcome", |_| K::OUTCOME_KW, ignore(case))]
    #[token("condition", |_| K::CONDITION_KW, ignore(case))]
    #[token("options", |_| K::OPTIONS_KW, ignore(case))]
    #[token("export", |_| K::EXPORT_KW, ignore(case))]
    #[token("dedup", |_| K::DEDUP_KW, ignore(case))]
    #[token("order", |_| K::ORDER_KW, ignore(case))]
    #[token("limit", |_| K::LIMIT_KW, ignore(case))]
    #[token("select", |_| K::SELECT_KW, ignore(case))]
    #[token("unselect", |_| K::UNSELECT_KW, ignore(case))]
    #[token("stage", |_| K::STAGE_KW, ignore(case))]
    #[token("and", |_| K::AND_KW, ignore(case))]
    #[token("or", |_| K::OR_KW, ignore(case))]
    #[token("not", |_| K::NOT_KW, ignore(case))]
    #[token("nocase", |_| K::NOCASE_KW, ignore(case))]
    #[token("in", |_| K::IN_KW, ignore(case))]
    #[token("regex", |_| K::REGEX_KW, ignore(case))]
    #[token("cidr", |_| K::CIDR_KW, ignore(case))]
    #[token("any", |_| K::ANY_KW, ignore(case))]
    #[token("all", |_| K::ALL_KW, ignore(case))]
    #[token("over", |_| K::OVER_KW, ignore(case))]
    #[token("by", |_| K::BY_KW, ignore(case))]
    #[token("before", |_| K::BEFORE_KW, ignore(case))]
    #[token("after", |_| K::AFTER_KW, ignore(case))]
    #[token("if", |_| K::IF_KW, ignore(case))]
    #[token("of", |_| K::OF_KW, ignore(case))]
    #[token("true", |_| K::TRUE_KW, ignore(case))]
    #[token("false", |_| K::FALSE_KW, ignore(case))]
    #[token("asc", |_| K::ASC_KW, ignore(case))]
    #[token("desc", |_| K::DESC_KW, ignore(case))]
    #[token("window_start", |_| K::WINDOW_START_KW, ignore(case))]
    #[token("window_end", |_| K::WINDOW_END_KW, ignore(case))]
    Keyword(K),
    #[regex(r"\$[A-Za-z_][A-Za-z0-9_]*")]
    Variable,
    #[regex(r"#[A-Za-z_][A-Za-z0-9_]*")]
    Count,
    #[regex(r"%[A-Za-z_][A-Za-z0-9_]*")]
    ReferenceList,
    #[regex(r"[0-9]+")]
    Integer,
    #[regex(r"[0-9]+\.[0-9]+")]
    Float,
    #[regex(r"[0-9]+[A-Za-z]+")]
    Duration,
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("[")]
    LBrack,
    #[token("]")]
    RBrack,
    #[token(",")]
    Comma,
    #[token(":")]
    Colon,
    #[token(".")]
    Dot,
    #[token("=")]
    Eq,
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
    #[token("!")]
    Bang,
}

/// What a `/` starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slash {
    Divide,
    Regex,
}

impl Tok {
    fn kind(self) -> K {
        match self {
            Self::Whitespace => K::WHITESPACE,
            Self::LineComment | Self::BlockComment => K::COMMENT,
            Self::Slash(Slash::Divide) => K::SLASH,
            Self::Slash(Slash::Regex) => K::REGEX_LIT,
            Self::String => K::STRING,
            Self::RawString => K::RAW_STRING,
            Self::Word => K::IDENT,
            Self::Keyword(kind) => kind,
            Self::Variable => K::VAR_TOKEN,
            Self::Count => K::COUNT_TOKEN,
            Self::ReferenceList => K::REF_LIST_TOKEN,
            Self::Integer => K::INTEGER,
            Self::Float => K::FLOAT,
            Self::Duration => K::DURATION,
            Self::LBrace => K::L_BRACE,
            Self::RBrace => K::R_BRACE,
            Self::LParen => K::L_PAREN,
            Self::RParen => K::R_PAREN,
            Self::LBrack => K::L_BRACK,
            Self::RBrack => K::R_BRACK,
            Self::Comma => K::COMMA,
            Self::Colon => K::COLON,
            Self::Dot => K::DOT,
            Self::Eq => K::EQ,
            Self::NotEq => K::NOT_EQ,
            Self::Lt => K::LT,
            Self::LtEq => K::LT_EQ,
            Self::Gt => K::GT,
            Self::GtEq => K::GT_EQ,
            Self::Plus => K::PLUS,
            Self::Minus => K::MINUS,
            Self::Star => K::STAR,
            Self::Percent => K::PERCENT,
            Self::Bang => K::BANG,
        }
    }
}

/// Past the `"`: the length of the string's rest, closing quote included.
/// A string ends at its quote, never at a newline; `\` takes the next
/// character (a newline excepted).
fn string_rest(rest: &str) -> Option<usize> {
    let mut chars = rest.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some(i + 1),
            '\n' => return None,
            '\\' => match chars.next() {
                Some((_, '\n')) | None => return None,
                Some(_) => {}
            },
            _ => {}
        }
    }
    None
}

fn string(lex: &mut logos::Lexer<'_, Tok>) -> bool {
    string_rest(lex.remainder()).map(|n| lex.bump(n)).is_some()
}

/// A backquoted string runs to the next backquote, over lines.
fn raw_string(lex: &mut logos::Lexer<'_, Tok>) -> bool {
    lex.remainder().find('`').map(|i| lex.bump(i + 1)).is_some()
}

/// `// ...` to the end of the line.
fn line_comment(lex: &mut logos::Lexer<'_, Tok>) {
    lex.bump(lex.remainder().find('\n').unwrap_or(lex.remainder().len()));
}

/// `/* ... */`, not nested: it ends at the first `*/`.
fn block_comment(lex: &mut logos::Lexer<'_, Tok>) -> bool {
    lex.remainder()
        .find("*/")
        .map(|i| lex.bump(i + 2))
        .is_some()
}

/// Past a `/`: the length of the regular expression's rest (its closing `/`
/// included), when one starts here. It does not start with `*`, `/`, `\`
/// followed by a newline, or a newline, and runs to the first `/` that no
/// `\` takes, never over a line.
fn regex_rest(rest: &str) -> Option<usize> {
    let mut chars = rest.char_indices();
    let (_, first) = chars.next()?;
    match first {
        '*' | '/' | '\n' => return None,
        '\\' => match chars.next() {
            Some((_, '\n')) | None => return None,
            Some(_) => {}
        },
        _ => {}
    }
    while let Some((i, c)) = chars.next() {
        match c {
            '/' => return Some(i + 1),
            '\n' => return None,
            '\\' => match chars.next() {
                Some((_, '\n')) | None => return None,
                Some(_) => {}
            },
            _ => {}
        }
    }
    None
}

fn slash(lex: &mut logos::Lexer<'_, Tok>) -> Slash {
    match regex_rest(lex.remainder()) {
        Some(n) => {
            lex.bump(n);
            Slash::Regex
        }
        None => Slash::Divide,
    }
}

/// The lexemes of `source`: they tile it, trivia included.
pub(crate) fn lex(source: &str) -> Vec<Lexeme> {
    let mut lexemes = opentide_parse::lex::<Tok>(source, |token, _| match token {
        Ok(token) => token.kind().raw(),
        Err(()) => K::ERROR_TOKEN.raw(),
    });
    mark_paths(&mut lexemes);
    lexemes
}

/// Re-kinds what only the neighbours decide: a dot or an index bracket with
/// no blank before it, after a variable, a name or `]`, belongs to a path,
/// and the word right after the dot is its segment.
fn mark_paths(lexemes: &mut [Lexeme]) {
    let mut prev: Option<(K, rowan::TextSize)> = None;
    for lexeme in lexemes {
        let kind = K::from_raw(lexeme.kind);
        if matches!(kind, K::WHITESPACE | K::COMMENT) {
            prev = None;
            continue;
        }
        let touching = prev.filter(|&(_, end)| end == lexeme.range.start());
        let after_path = touching.is_some_and(|(k, _)| {
            matches!(k, K::VAR_TOKEN | K::IDENT | K::FIELD_NAME | K::R_BRACK)
        });
        let kind = match kind {
            K::DOT if after_path => K::ACCESS_DOT,
            K::L_BRACK if after_path => K::INDEX_L_BRACK,
            k if k.is_word() && touching.is_some_and(|(p, _)| p == K::ACCESS_DOT) => K::FIELD_NAME,
            k => k,
        };
        lexeme.kind = kind.raw();
        prev = Some((kind, lexeme.range.end()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(kind, text)` of the lexemes of `source` that are not whitespace.
    fn kinds(source: &str) -> Vec<(K, &str)> {
        lex(source)
            .iter()
            .filter(|l| l.kind != K::WHITESPACE.raw())
            .map(|l| {
                (
                    K::from_raw(l.kind),
                    &source[std::ops::Range::<usize>::from(l.range)],
                )
            })
            .collect()
    }

    #[test]
    fn keywords_are_read_in_any_case_and_only_whole() {
        for source in ["rule", "RULE", "rUlE", "Window_Start"] {
            assert!(kinds(source)[0].0.is_keyword(), "{source}");
        }
        for source in [
            "metadata",
            "rules",
            "ruler_",
            "meta1",
            "every",
            "Cross",
            "graph_append",
        ] {
            assert_eq!(kinds(source)[0].0, K::IDENT, "{source}");
        }
    }

    #[test]
    fn a_path_is_marked_by_what_touches_it() {
        let k = kinds("$e.network.dhcp.options[\"k\"].x");
        let expected = [
            K::VAR_TOKEN,
            K::ACCESS_DOT,
            K::FIELD_NAME,
            K::ACCESS_DOT,
            K::FIELD_NAME,
            K::ACCESS_DOT,
            K::FIELD_NAME,
            K::INDEX_L_BRACK,
            K::STRING,
            K::R_BRACK,
            K::ACCESS_DOT,
            K::FIELD_NAME,
        ];
        assert_eq!(k.iter().map(|k| k.0).collect::<Vec<_>>(), expected);
        // A blank before the dot or the bracket ends the path; `%table.column` has a plain dot.
        assert_eq!(kinds("$e .x")[1].0, K::DOT);
        assert_eq!(kinds("$e\n[1]")[1].0, K::L_BRACK);
        assert_eq!(kinds("%t.col")[1].0, K::DOT);
        assert_eq!(kinds("any of[$a]")[2].0, K::L_BRACK);
        assert_eq!(kinds("strings.to_lower(x)")[2].0, K::FIELD_NAME);
        // A comment is a blank too.
        assert_eq!(kinds("$e/**/.x")[2].0, K::DOT);
    }

    #[test]
    fn a_slash_is_a_regex_when_one_reads_and_else_a_division() {
        assert_eq!(kinds(r"= /a\/b+/ nocase")[1], (K::REGEX_LIT, r"/a\/b+/"));
        assert_eq!(kinds("a / b")[1].0, K::SLASH);
        assert_eq!(kinds("a /b\n/ c")[1].0, K::SLASH, "a regex stays on a line");
        assert_eq!(kinds("// a\nx")[0], (K::COMMENT, "// a"));
        assert_eq!(kinds("/* a */ x")[0], (K::COMMENT, "/* a */"));
        assert_eq!(kinds("/* a")[0].0, K::ERROR_TOKEN, "never closed");
        assert_eq!(kinds("/*/ x */")[0], (K::COMMENT, "/*/ x */"));
    }

    #[test]
    fn strings_and_numbers() {
        assert_eq!(kinds(r#""a\"b\\""#)[0], (K::STRING, r#""a\"b\\""#));
        assert_eq!(kinds("\"abc\n")[0].0, K::ERROR_TOKEN);
        assert_eq!(kinds("`a\nb`")[0], (K::RAW_STRING, "`a\nb`"));
        assert_eq!(kinds("`a")[0].0, K::ERROR_TOKEN);
        let k = kinds("1 1.5 10m 2d $x #e %l");
        let expected = [
            K::INTEGER,
            K::FLOAT,
            K::DURATION,
            K::DURATION,
            K::VAR_TOKEN,
            K::COUNT_TOKEN,
            K::REF_LIST_TOKEN,
        ];
        assert_eq!(k.iter().map(|k| k.0).collect::<Vec<_>>(), expected);
    }

    /// A token of a million repeats must not overflow a small stack: the
    /// scanners are loops (the logos stack trap, found in the kuery review).
    #[test]
    fn a_huge_token_does_not_overflow_the_stack() {
        let n = 1_000_000;
        let sources = [
            format!("\"{}\"", "\\a".repeat(n)),
            format!("/{}/", "\\a".repeat(n)),
            format!("`{}`", "a".repeat(n)),
            format!("/*{}*/", "a".repeat(n)),
            format!("// {}", "a".repeat(n)),
            "a".repeat(n),
            "$a".repeat(n),
            " ".repeat(n),
        ];
        std::thread::Builder::new()
            .stack_size(1 << 20)
            .spawn(move || {
                for source in &sources {
                    let lexemes = lex(source);
                    assert_eq!(
                        lexemes.last().map(|l| usize::from(l.range.end())),
                        Some(source.len())
                    );
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
