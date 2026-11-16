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
#[logos(extras = Context)]
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
    #[token("%", percent)]
    Percent(bool),
    #[token("!")]
    Bang,
}

/// What the lexer knows of the text before: tree-sitter lexed what the parser
/// could take next, and inside a group (parentheses, brackets) a new statement
/// cannot start, so after an operand a `/` is a division and `%name` is a
/// modulo and a name. At the top of a section both start a statement (a
/// regex, a reference list), the longer match.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Context {
    /// Open parentheses and brackets.
    depth: u32,
    /// Whether the last significant token ends an operand.
    operand: bool,
}

impl Context {
    /// Whether the next token can only continue the expression.
    fn continues(self) -> bool {
        self.depth > 0 && self.operand
    }

    /// The context after a token of `kind`.
    fn after(mut self, kind: K) -> Self {
        match kind {
            K::WHITESPACE | K::COMMENT => {}
            K::L_PAREN | K::L_BRACK => {
                self.depth += 1;
                self.operand = false;
            }
            K::R_PAREN | K::R_BRACK => {
                self.depth = self.depth.saturating_sub(1);
                self.operand = true;
            }
            K::L_BRACE | K::R_BRACE => self = Self::default(),
            K::IDENT
            | K::VAR_TOKEN
            | K::COUNT_TOKEN
            | K::REF_LIST_TOKEN
            | K::STRING
            | K::RAW_STRING
            | K::REGEX_LIT
            | K::INTEGER
            | K::FLOAT
            | K::DURATION
            | K::TRUE_KW
            | K::FALSE_KW
            | K::WINDOW_START_KW
            | K::WINDOW_END_KW => self.operand = true,
            _ => self.operand = false,
        }
        self
    }
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
            Self::Percent(true) => K::REF_LIST_TOKEN,
            Self::Percent(false) => K::PERCENT,
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
    match regex_rest(lex.remainder()).filter(|_| !lex.extras.continues()) {
        Some(n) => {
            lex.bump(n);
            Slash::Regex
        }
        None => Slash::Divide,
    }
}

/// `start..end` as a range; a source past 4 GiB is clamped.
fn text_range(start: usize, end: usize) -> rowan::TextRange {
    let size = |n: usize| rowan::TextSize::from(u32::try_from(n).unwrap_or(u32::MAX));
    rowan::TextRange::new(size(start), size(end.max(start)))
}

/// `%name` is a reference list, unless the expression goes on (a modulo).
fn percent(lex: &mut logos::Lexer<'_, Tok>) -> bool {
    let rest = lex.remainder();
    let starts = rest
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    if !starts || lex.extras.continues() {
        return false;
    }
    let n = rest
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count();
    lex.bump(n);
    true
}

/// The lexemes of `source`: they tile it, trivia included. As the toolkit's
/// `lex` (an error is one character, and lexing resumes after it), with the
/// context of the text before each token.
pub(crate) fn lex(source: &str) -> Vec<Lexeme> {
    let mut out: Vec<Lexeme> = Vec::new();
    let mut context = Context::default();
    let mut base = 0;
    'restart: while base < source.len() {
        let mut lexer = Tok::lexer_with_extras(&source[base..], context);
        while let Some(token) = lexer.next() {
            let span = lexer.span();
            let start = base + span.start;
            let (kind, end) = match token {
                Ok(token) => (token.kind(), base + span.end),
                Err(()) => (K::ERROR_TOKEN, source.ceil_char_boundary(start + 1)),
            };
            out.push(Lexeme {
                kind: kind.raw(),
                range: text_range(start, end),
            });
            context = context.after(kind);
            if kind == K::ERROR_TOKEN {
                base = end;
                continue 'restart;
            }
            lexer.extras = context;
        }
        break;
    }
    mark_paths(&mut out);
    out
}

/// Re-kinds what only the neighbours decide: a dot or an index bracket with
/// no blank before it, after a variable, a name or `]`, belongs to a path;
/// the word after the dot is its segment, with blanks or comments between
/// them or not (tree-sitter's `token.immediate` bound the dot to what comes
/// before it, not the segment to the dot).
fn mark_paths(lexemes: &mut [Lexeme]) {
    // The last significant token's kind and end, and whether trivia came since.
    let mut prev: Option<(K, rowan::TextSize)> = None;
    // The kind before `prev`: the name after a plain dot is a table column,
    // and no path continues it.
    let mut before: Option<K> = None;
    let mut touching = false;
    for lexeme in lexemes {
        let kind = K::from_raw(lexeme.kind);
        if matches!(kind, K::WHITESPACE | K::COMMENT) {
            touching = false;
            continue;
        }
        let after_path = touching
            && prev.is_some_and(|(k, end)| {
                end == lexeme.range.start()
                    && matches!(k, K::VAR_TOKEN | K::IDENT | K::FIELD_NAME | K::R_BRACK)
                    && !(k == K::IDENT && before == Some(K::DOT))
            });
        let kind = match kind {
            K::DOT if after_path => K::ACCESS_DOT,
            K::L_BRACK if after_path => K::INDEX_L_BRACK,
            k if k.is_word() && prev.is_some_and(|(p, _)| p == K::ACCESS_DOT) => K::FIELD_NAME,
            k => k,
        };
        lexeme.kind = kind.raw();
        before = prev.map(|(k, _)| k);
        prev = Some((kind, lexeme.range.end()));
        touching = true;
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
        // A table column is no path: a bracket after it opens an array.
        assert_eq!(kinds("%t .col[1]")[3].0, K::L_BRACK);
        // Inside a group an operand goes on: a modulo, a division.
        let k: Vec<K> = kinds("($a = %x %y.z)").iter().map(|k| k.0).collect();
        assert!(
            k.contains(&K::PERCENT) && k.iter().filter(|k| **k == K::REF_LIST_TOKEN).count() == 1
        );
        assert_eq!(
            kinds("($a / $b / $c)")
                .iter()
                .filter(|k| k.0 == K::SLASH)
                .count(),
            2
        );
        assert_eq!(kinds("f($a, /x/)")[4].0, K::REGEX_LIT);
        assert_eq!(kinds("any of[$a]")[2].0, K::L_BRACK);
        assert_eq!(kinds("strings.to_lower(x)")[2].0, K::FIELD_NAME);
        // The segment after a dot may follow a blank (tree-sitter accepted it).
        assert_eq!(kinds("$e. and")[2].0, K::FIELD_NAME);
        assert_eq!(kinds("a.\n b")[2].0, K::FIELD_NAME);
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

    /// B1 of the review of #1375: tree-sitter lexed `/`, `%name` and the
    /// segment after a dot by what the parser took next.
    #[test]
    fn what_the_parser_takes_next_decides_a_slash_a_percent_and_a_segment() {
        let kinds_of = |s: &str| kinds(s).iter().map(|k| k.0).collect::<Vec<_>>();
        for source in [
            "$z = ($e.a/$e.b/2)",
            "($a/b/2)",
            "(f($a) /re/ 2)",
            "f($a / $b / $c)",
            "[$a / $b / 1]",
        ] {
            let k = kinds_of(source);
            assert!(!k.contains(&K::REGEX_LIT), "{source}: {k:?}");
            assert_eq!(k.iter().filter(|k| **k == K::SLASH).count(), 2, "{source}");
        }
        for source in [
            "$z = if($a %b, 1, 2)",
            "($a %b)",
            "f($a %b)",
            "[$a %b]",
            "($g.graph.entity.ip  %hosts.ip)",
        ] {
            let k = kinds_of(source);
            assert!(!k.contains(&K::REF_LIST_TOKEN), "{source}: {k:?}");
            assert!(k.contains(&K::PERCENT), "{source}");
        }
        // At the top of a section both start a statement.
        assert!(kinds_of("$a %b").contains(&K::REF_LIST_TOKEN));
        assert!(kinds_of("$a / $b / $c").contains(&K::REGEX_LIT));
        // Operands start a regex or a list again after an operator or a comma.
        assert!(kinds_of("f($a, %l)").contains(&K::REF_LIST_TOKEN));
        assert!(kinds_of("($a = /x/)").contains(&K::REGEX_LIT));
        // The segment after a dot may follow blanks and newlines.
        for source in [
            "$e.principal. hostname = 1",
            "$e.principal.\n hostname",
            "a.\n/*c*/b",
        ] {
            assert!(kinds_of(source).contains(&K::FIELD_NAME), "{source}");
            assert!(!kinds_of(source).contains(&K::ERROR_TOKEN), "{source}");
        }
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
