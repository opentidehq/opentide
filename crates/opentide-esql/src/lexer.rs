//! The ES|QL lexer: logos for the tokens of expressions, and the modes the
//! tree-sitter grammar's context-aware lexing and its C scanner gave it.
//!
//! tree-sitter lexed what the parser could accept next: index patterns after
//! `FROM`, name patterns after `KEEP`, raw text after an unknown command. A
//! pre-lexed token stream has no parser to ask, so the lexer follows the
//! pipeline itself: a command's first word picks the mode of its operands
//! (`mode_of`), `|` starts a command, `(` and `)` push and pop the mode (a
//! subquery, a `FORK` branch, `EXPLAIN (…)`). Words are not keywords here:
//! every word is [`K::WORD`] and the parser decides.
//!
//! The scanner's job is [`block_comment`]: Elasticsearch nests `/* */`, and
//! the scanner simulated its lexer's readings of a nested opener. The lexer
//! tiles the source, whitespace and comments included, and never skips.

use crate::syntax::SyntaxKind as K;
use logos::Logos;
use opentide_parse::Lexeme;
use rowan::{TextRange, TextSize};

/// The tokens of expressions (and the punctuation every mode shares).
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    #[regex(r"[a-zA-Z][a-zA-Z0-9_]*|[_@][a-zA-Z0-9_]+")]
    Word,
    #[regex(r"[0-9]+(\.[0-9]*)?([eE][+-]?[0-9]+)?|\.[0-9]+([eE][+-]?[0-9]+)?")]
    Number,
    #[regex(r"\?\??([a-zA-Z_][a-zA-Z0-9_]*|[0-9]+)?")]
    Param,
    #[token("|")]
    Pipe,
    #[token(",")]
    Comma,
    #[token(";")]
    Semi,
    #[token(".")]
    Dot,
    #[token(":")]
    Colon,
    #[token("::")]
    ColonColon,
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
    #[token("/")]
    Slash,
    #[token("%")]
    Percent,
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

impl Tok {
    fn kind(self) -> K {
        match self {
            Self::Word => K::WORD,
            Self::Number => K::NUMBER_LIT,
            Self::Param => K::PARAM,
            Self::Pipe => K::PIPE,
            Self::Comma => K::COMMA,
            Self::Semi => K::SEMI,
            Self::Dot => K::DOT,
            Self::Colon => K::COLON,
            Self::ColonColon => K::COLON_COLON,
            Self::Eq => K::EQ,
            Self::EqEq => K::EQ_EQ,
            Self::NotEq => K::NOT_EQ,
            Self::Lt => K::LT,
            Self::LtEq => K::LT_EQ,
            Self::Gt => K::GT,
            Self::GtEq => K::GT_EQ,
            Self::Plus => K::PLUS,
            Self::Minus => K::MINUS,
            Self::Star => K::STAR_TOKEN,
            Self::Slash => K::SLASH,
            Self::Percent => K::PERCENT,
            Self::LParen => K::L_PAREN,
            Self::RParen => K::R_PAREN,
            Self::LBrack => K::L_BRACK,
            Self::RBrack => K::R_BRACK,
            Self::LBrace => K::L_BRACE,
            Self::RBrace => K::R_BRACE,
        }
    }
}

/// How the operands of a command are lexed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Where a query starts (a source command): its first word is read whole.
    StartQuery,
    /// After `|` (a processing command): its first word is read whole.
    StartCommand,
    /// Expressions.
    Expr,
    /// Name patterns: a word may hold `*`.
    Names,
    /// Index patterns, clusters and selectors.
    Source,
    /// An `ENRICH` policy name.
    Policy,
    /// The text of a command the grammar does not know.
    Unknown,
    /// `PROMQL` text.
    Promql,
    /// After `LOOKUP`, `LEFT`, `RIGHT` or `FULL`: `JOIN` comes next.
    JoinKw,
}

/// What a command needs of the lexer beyond its mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmd {
    Other,
    /// `LOOKUP JOIN idx ON …`: the sources end at `ON`.
    Join,
    /// `ENRICH policy ON field WITH …`.
    Enrich,
    /// `HIGHLIGHT query ON names WITH {…}`.
    Highlight,
    /// `FILLNULL value ON names`.
    FillNull,
    /// `FORK`: every `(` opens a branch of processing commands.
    Fork,
    /// `EXPLAIN`: its `(` opens a query.
    Explain,
}

#[derive(Clone, Copy, Debug)]
struct Frame {
    mode: Mode,
    cmd: Cmd,
}

const START_QUERY: Frame = Frame {
    mode: Mode::StartQuery,
    cmd: Cmd::Other,
};

const START_COMMAND: Frame = Frame {
    mode: Mode::StartCommand,
    cmd: Cmd::Other,
};

/// The mode and flavour of the operands of the command that starts with
/// `word` (lower case), at the start of a query (`query`, and `top` when it
/// is the file's, where `SET` may precede it) or after a pipe; `None` for a
/// command the grammar does not know there.
fn mode_of(word: &str, query: bool, top: bool) -> Option<Frame> {
    let frame = |mode, cmd| Some(Frame { mode, cmd });
    let expr = |cmd| frame(Mode::Expr, cmd);
    if query {
        return match word {
            "from" | "ts" => frame(Mode::Source, Cmd::Other),
            "promql" => frame(Mode::Promql, Cmd::Other),
            "explain" => expr(Cmd::Explain),
            "row" | "show" => expr(Cmd::Other),
            "set" if top => expr(Cmd::Other),
            _ => None,
        };
    }
    match word {
        "keep" | "drop" | "rename" => frame(Mode::Names, Cmd::Other),
        "enrich" => frame(Mode::Policy, Cmd::Enrich),
        "lookup" | "left" | "right" | "full" => frame(Mode::JoinKw, Cmd::Other),
        "fork" => expr(Cmd::Fork),
        "highlight" => expr(Cmd::Highlight),
        "fillnull" => expr(Cmd::FillNull),
        "where" | "eval" | "sort" | "limit" | "stats" | "inline" | "inlinestats" | "dissect"
        | "grok" | "mv_expand" | "change_point" | "completion" | "rerank" | "sample" | "fuse"
        | "uri_parts" | "registered_domain" | "user_agent" | "ip_location" | "metrics_info"
        | "ts_info" | "ts_collapse" | "dedup" | "mmr" | "dense_vector" => expr(Cmd::Other),
        _ => None,
    }
}

/// The length of the text at the start of `rest` made of characters `ok`
/// takes.
fn take(rest: &str, ok: impl Fn(char) -> bool) -> usize {
    rest.find(|c| !ok(c)).unwrap_or(rest.len())
}

/// An index pattern: runs of characters other than ``:"=|,[]/()`` and
/// whitespace, where a `/` joins the next character unless that is `*`.
fn source_text(rest: &str) -> usize {
    let plain = |c: char| !c.is_whitespace() && !":\"=|,[]/()".contains(c);
    let mut end = 0;
    let mut chars = rest.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if plain(c) {
            end = i + c.len_utf8();
        } else if c == '/'
            && let Some(&(_, next)) = chars.peek()
            && plain(next)
            && next != '*'
        {
            chars.next();
            end = i + 1 + next.len_utf8();
        } else {
            break;
        }
    }
    end
}

/// A nested block comment at the start of `rest` (which begins `/*`), as
/// the old C scanner read it: the length of the comment, or `None` when it
/// is never closed (the `/` is then an operator). The scanner kept every
/// reading of the text Elasticsearch's lexer could take (a depth, and half
/// of a two-character delimiter seen), in the order of its preference
/// (close, then open a nested comment, then plain text); the first reading
/// to close the outermost comment records its end, drops the readings of
/// lower preference, and the higher ones may still find a longer comment.
fn block_comment(rest: &str, budget: &mut usize) -> Option<usize> {
    #[derive(Clone, Copy, PartialEq)]
    enum Half {
        None,
        Slash,
        Star,
    }
    /// The scanner's cap: a reading past it is dropped.
    const MAX_READINGS: usize = 64;
    fn push(out: &mut Vec<(u16, Half)>, reading: (u16, Half)) {
        if out.len() < MAX_READINGS && !out.contains(&reading) {
            out.push(reading);
        }
    }
    let mut readings = vec![(1u16, Half::None)];
    let mut next = Vec::with_capacity(MAX_READINGS);
    let mut end = None;
    for (i, c) in rest.bytes().enumerate().skip(2) {
        if readings.is_empty() {
            break;
        }
        // The scanner reads on to the end of the text after a close, for a
        // longer comment: `/*` repeated would read quadratically. Past the
        // budget (a multiple of the source) the first close is the end.
        if *budget < readings.len() {
            return end.or_else(|| rest.get(2..)?.find("*/").map(|at| at + 4));
        }
        *budget -= readings.len();
        next.clear();
        for &(depth, half) in &readings {
            match half {
                Half::Star if c == b'/' => {
                    if depth == 1 {
                        end = Some(i + 1);
                        break;
                    }
                    push(&mut next, (depth - 1, Half::None));
                }
                Half::Slash if c == b'*' && depth < u16::MAX => {
                    push(&mut next, (depth + 1, Half::None));
                }
                Half::None => {
                    match c {
                        b'*' => push(&mut next, (depth, Half::Star)),
                        b'/' => push(&mut next, (depth, Half::Slash)),
                        _ => {}
                    }
                    push(&mut next, (depth, Half::None));
                }
                _ => {}
            }
        }
        std::mem::swap(&mut readings, &mut next);
    }
    end
}

/// A string literal at the start of `rest` (which begins with `"`): a
/// triple-quoted one on one line, or a double-quoted one with escapes.
fn string(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    if rest.starts_with("\"\"\"") {
        // The body holds no line break and no run of three quotes.
        let mut i = 3;
        while i < bytes.len() && bytes[i] != b'\r' && bytes[i] != b'\n' {
            if bytes[i..].starts_with(b"\"\"\"") {
                let quotes = bytes[i + 3..]
                    .iter()
                    .take(2)
                    .take_while(|&&b| b == b'"')
                    .count();
                return Some(i + 3 + quotes);
            }
            i += 1;
        }
    }
    let mut i = 1;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'"' => return Some(i + 1),
            b'\\' if bytes.get(i + 1).is_some_and(|&n| n != b'\n') => i += 2,
            b'\\' | b'\r' | b'\n' => return None,
            _ => i += 1,
        }
    }
    None
}

/// A quoted identifier at the start of `rest` (which begins with a backtick):
/// one or more characters, a doubled backtick standing for one; the longest
/// reading wins, so a backtick that could close it ends it.
fn quoted_identifier(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    let (mut i, mut count, mut end) = (1, 0, None);
    while i < bytes.len() {
        if bytes[i] == b'`' {
            if count > 0 {
                end = Some(i + 1);
            }
            if bytes.get(i + 1) != Some(&b'`') {
                break;
            }
            i += 2;
        } else {
            i += rest[i..].chars().next().map_or(1, char::len_utf8);
        }
        count += 1;
    }
    end
}

struct Driver<'s> {
    source: &'s str,
    pos: usize,
    frame: Frame,
    stack: Vec<Frame>,
    /// Tokens since the mode began (a policy or a join target has at least one
    /// before the `ON` that ends it).
    seen: usize,
    /// Whether the last token that is not trivia was the word `in`.
    after_in: bool,
    /// Whether a `/*` found no close: the plain-text reading closes at any
    /// `*/` after it, so none follows, and a later `/*` would not close
    /// either. Without it, `/*` repeated is read quadratically.
    no_block_close: bool,
    /// What the readings of block comments may still cost (reading steps).
    budget: usize,
}

impl Driver<'_> {
    /// The next token's kind and length.
    fn token(&mut self) -> (K, usize) {
        let rest = &self.source[self.pos..];
        let spaces = take(rest, char::is_whitespace);
        if spaces > 0 {
            return (K::WHITESPACE, spaces);
        }
        if rest.starts_with("//") {
            return (K::COMMENT, rest.find(['\r', '\n']).unwrap_or(rest.len()));
        }
        if rest.starts_with("/*") && !self.no_block_close {
            match block_comment(rest, &mut self.budget) {
                Some(len) => return (K::COMMENT, len),
                None => self.no_block_close = true,
            }
        }
        if rest.starts_with('"')
            && let Some(len) = string(rest)
        {
            return (K::STRING_LIT, len);
        }
        let (text_kind, len) = match self.frame.mode {
            Mode::StartQuery | Mode::StartCommand => (
                K::COMMAND_WORD,
                take(rest, |c| !c.is_whitespace() && !"[]()/|\"".contains(c)),
            ),
            Mode::Source => (K::SOURCE_TEXT, source_text(rest)),
            Mode::Policy => (
                K::POLICY_PART,
                take(rest, |c| !" \t\r\n\\/?\"<>|,#:()".contains(c)),
            ),
            Mode::Unknown => (
                K::UNKNOWN_WORD,
                take(rest, |c| !c.is_whitespace() && !"|\"".contains(c)),
            ),
            Mode::Promql => (
                K::PROMQL_WORD,
                take(rest, |c| !c.is_whitespace() && !"|()\"".contains(c)),
            ),
            Mode::Expr | Mode::Names | Mode::JoinKw => (K::ERROR_TOKEN, 0),
        };
        if len > 0 {
            return (text_kind, len);
        }
        if rest.starts_with('`')
            && let Some(len) = quoted_identifier(rest)
        {
            return (K::QUOTED_IDENT, len);
        }
        let mut lexer = Tok::lexer(rest);
        match lexer.next() {
            Some(Ok(tok)) => {
                let mut len = lexer.span().end;
                if self.frame.mode == Mode::Names && matches!(tok, Tok::Word | Tok::Star) {
                    len += take(&rest[len..], |c| {
                        c.is_ascii_alphanumeric() || c == '_' || c == '*'
                    });
                }
                let kind = if self.frame.mode == Mode::Names && tok == Tok::Star {
                    K::WORD
                } else {
                    tok.kind()
                };
                (kind, len)
            }
            _ => (
                K::ERROR_TOKEN,
                rest.chars().next().map_or(1, char::len_utf8),
            ),
        }
    }

    /// Updates the mode for `kind` (the text is `text`) and returns the kind
    /// the lexeme gets.
    fn follow(&mut self, kind: K, text: &str) -> K {
        if matches!(kind, K::WHITESPACE | K::COMMENT) {
            return kind;
        }
        let word = |w: &str| text.eq_ignore_ascii_case(w);
        let was_in = std::mem::take(&mut self.after_in);
        self.seen += 1;
        let (mode, cmd) = (self.frame.mode, self.frame.cmd);
        let mut kind = kind;
        match kind {
            K::PIPE => self.set(START_COMMAND),
            K::SEMI if self.stack.is_empty() => self.set(START_QUERY),
            K::L_PAREN => self.open(was_in),
            K::R_PAREN => {
                if let Some(frame) = self.stack.pop() {
                    self.set(frame);
                }
            }
            K::COMMAND_WORD if matches!(mode, Mode::StartQuery | Mode::StartCommand) => {
                match mode_of(
                    &text.to_ascii_lowercase(),
                    mode == Mode::StartQuery,
                    self.stack.is_empty(),
                ) {
                    Some(frame) => {
                        kind = K::WORD;
                        self.set(frame);
                    }
                    None => self.set(Frame {
                        mode: Mode::Unknown,
                        cmd: Cmd::Other,
                    }),
                }
            }
            K::UNKNOWN_WORD if text == ")" && !self.stack.is_empty() => {
                kind = K::R_PAREN;
                if let Some(frame) = self.stack.pop() {
                    self.set(frame);
                }
            }
            K::POLICY_PART if self.seen > 1 && (word("on") || word("with")) => {
                kind = K::WORD;
                self.set(Frame {
                    mode: Mode::Names,
                    cmd,
                });
            }
            K::SOURCE_TEXT if cmd == Cmd::Join && self.seen > 1 && word("on") => {
                kind = K::WORD;
                self.set(Frame {
                    mode: Mode::Expr,
                    cmd: Cmd::Other,
                });
            }
            K::WORD => match mode {
                Mode::JoinKw => {
                    let join = word("join");
                    self.set(Frame {
                        mode: if join { Mode::Source } else { Mode::Expr },
                        cmd: if join { Cmd::Join } else { Cmd::Other },
                    });
                }
                Mode::Expr if matches!(cmd, Cmd::FillNull | Cmd::Highlight) && word("on") => {
                    if self.stack.is_empty() {
                        self.set(Frame {
                            mode: Mode::Names,
                            cmd,
                        });
                    }
                }
                Mode::Names if cmd == Cmd::Highlight && word("with") => {
                    self.set(Frame {
                        mode: Mode::Expr,
                        cmd: Cmd::Other,
                    });
                }
                Mode::Expr => self.after_in = word("in"),
                _ => {}
            },
            _ => {}
        }
        kind
    }

    fn set(&mut self, frame: Frame) {
        self.frame = frame;
        self.seen = 0;
    }

    /// `(`: a subquery (in a source list, after `IN`, or at a `FORK` or
    /// `EXPLAIN`) starts a command; any other parenthesis keeps the mode.
    fn open(&mut self, after_in: bool) {
        let query = match (self.frame.mode, self.frame.cmd) {
            (Mode::Source, _) | (_, Cmd::Explain) => true,
            (_, Cmd::Fork) => {
                self.stack.push(self.frame);
                self.set(START_COMMAND);
                return;
            }
            (Mode::Expr, _) if after_in => {
                let rest = self.source[self.pos..].trim_start();
                let word = &rest[..take(rest, |c| c.is_ascii_alphanumeric() || c == '_')];
                ["from", "ts", "row"]
                    .iter()
                    .any(|w| word.eq_ignore_ascii_case(w))
            }
            _ => false,
        };
        self.stack.push(self.frame);
        if query {
            self.set(START_QUERY);
        }
    }
}

/// The lexemes of `source`: they tile it, trivia included.
pub(crate) fn lex(source: &str) -> Vec<Lexeme> {
    let mut driver = Driver {
        source,
        pos: 0,
        frame: START_QUERY,
        stack: Vec::new(),
        seen: 0,
        after_in: false,
        no_block_close: false,
        budget: 16 * source.len() + 200_000,
    };
    let mut out = Vec::new();
    while driver.pos < source.len() {
        let (kind, len) = driver.token();
        let end = driver.pos + len.max(1);
        let text = &source[driver.pos..end];
        let offset = |n: usize| TextSize::from(u32::try_from(n).unwrap_or(u32::MAX));
        let range = TextRange::new(offset(driver.pos), offset(end));
        driver.pos = end;
        let kind = driver.follow(kind, text);
        out.push(Lexeme {
            kind: kind.raw(),
            range,
        });
    }
    out
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
                let kind = <crate::syntax::Lang as rowan::Language>::kind_from_raw(l.kind);
                (kind, &source[std::ops::Range::<usize>::from(l.range)])
            })
            .collect()
    }

    #[test]
    fn nested_comments_follow_elasticsearchs_lexer() {
        for (source, comment) in [
            ("/* a /* b */ c */ x", "/* a /* b */ c */"),
            ("/* a /* b */ x", "/* a /* b */"),
            ("/* a */ */", "/* a */"),
            ("// a\nx", "// a"),
        ] {
            assert_eq!(kinds(source)[0], (K::COMMENT, comment), "{source}");
        }
        // Never closed: the `/` is an operator and the comment's text is lexed on.
        assert_eq!(kinds("FROM a | EVAL /* a /* b")[4], (K::SLASH, "/"));
        assert_eq!(
            kinds("FROM a | EVAL /* a */ */").last(),
            Some(&(K::SLASH, "/"))
        );
    }

    #[test]
    fn strings_and_quoted_identifiers() {
        let k = |s: &str| {
            let source = format!("FROM a | EVAL {s}");
            let (kind, text) = kinds(&source)[4];
            (kind, text.to_owned())
        };
        for (text, kind) in [
            (r#""a\"b\\""#, K::STRING_LIT),
            (r#""""a "b" c""""#, K::STRING_LIT),
            ("`a``b`", K::QUOTED_IDENT),
        ] {
            assert_eq!(k(text), (kind, text.to_owned()));
        }
        assert_eq!(k(r#"""x"#), (K::STRING_LIT, r#""""#.to_owned()));
        assert_eq!(k("\"abc\n").0, K::ERROR_TOKEN);
        assert_eq!(k("`a``"), (K::QUOTED_IDENT, "`a`".to_owned()));
        assert_eq!(k("``").0, K::ERROR_TOKEN);
    }

    #[test]
    fn numbers_and_parameters() {
        for text in ["1", "1.", "1.5e+3", ".5", "2e10"] {
            assert_eq!(
                kinds(&format!("FROM a | eval {text}"))[4],
                (K::NUMBER_LIT, text)
            );
        }
        let parts = kinds("FROM a | eval 1e");
        assert_eq!((parts[4], parts[5]), ((K::NUMBER_LIT, "1"), (K::WORD, "e")));
        assert_eq!(kinds("FROM a | eval ??a, ?1, ?")[4].0, K::PARAM);
    }

    #[test]
    fn a_command_picks_the_mode_of_its_operands() {
        // Index patterns, clusters, selectors and METADATA fields are source text.
        let k = kinds("FROM c*:logs-*::data,a/b METADATA _id | KEEP a*b, `c`.d* | LIMIT 1");
        let texts: Vec<_> = k.iter().map(|(_, t)| *t).collect();
        assert_eq!(
            texts[..9],
            [
                "FROM", "c*", ":", "logs-*", "::", "data", ",", "a/b", "METADATA"
            ]
        );
        assert_eq!(
            (k[1].0, k[3].0, k[7].0, k[9].0),
            (
                K::SOURCE_TEXT,
                K::SOURCE_TEXT,
                K::SOURCE_TEXT,
                K::SOURCE_TEXT
            )
        );
        // A name pattern may hold `*`; in an expression it is an operator.
        assert!(k.contains(&(K::WORD, "a*b")) && k.contains(&(K::WORD, "d*")));
        assert_eq!(
            kinds("FROM a | EVAL a*b")[4..]
                .iter()
                .map(|k| k.0)
                .collect::<Vec<_>>(),
            [K::WORD, K::STAR_TOKEN, K::WORD]
        );
        // An unknown command and PROMQL are text up to the pipe.
        assert_eq!(
            kinds("FROM a | WEHRE x == 1")[3..]
                .iter()
                .map(|k| k.0)
                .collect::<Vec<_>>(),
            [
                K::COMMAND_WORD,
                K::UNKNOWN_WORD,
                K::UNKNOWN_WORD,
                K::UNKNOWN_WORD
            ]
        );
        assert_eq!(
            kinds("PROMQL rate(a[5m]) | LIMIT 1")[1],
            (K::PROMQL_WORD, "rate")
        );
    }

    #[test]
    fn a_command_is_known_only_where_the_grammar_expects_it() {
        // `WHERE` starts no query, and `FROM` is no processing command: both are unknown text.
        let k = kinds("WHERE x==1");
        assert_eq!((k[0].0, k[1]), (K::COMMAND_WORD, (K::UNKNOWN_WORD, "x==1")));
        assert_eq!(kinds("FROM a | FROM b")[3].0, K::COMMAND_WORD);
        assert_eq!(kinds("SET a = 1; FROM a")[0].0, K::WORD);
        assert_eq!(kinds("FROM a, (SET b)")[4].0, K::COMMAND_WORD);
    }

    #[test]
    fn modes_follow_subqueries_policies_and_joins() {
        // A subquery is a query again, then the list goes on.
        let k = kinds("FROM a, (FROM b | WHERE x) METADATA _id");
        assert_eq!(k.last(), Some(&(K::SOURCE_TEXT, "_id")));
        assert_eq!(k[7], (K::WORD, "WHERE"));
        // `IN (FROM ...)` is a subquery; `IN (a, b)` is not.
        assert_eq!(kinds("FROM a | EVAL x IN (FROM b)")[7], (K::WORD, "FROM"));
        assert_eq!(kinds("FROM a | EVAL x IN (a, from)")[7], (K::WORD, "a"));
        assert_eq!(
            kinds("FROM a | WHERE x IN (from_a)")[7],
            (K::WORD, "from_a")
        );
        // ENRICH reads a policy name, then name patterns.
        let k = kinds("FROM a | ENRICH ctx:on_policy ON a* WITH n = f*");
        assert_eq!(
            (k[4].0, k[6].0, k[7].0, k[8].0),
            (K::POLICY_PART, K::POLICY_PART, K::WORD, K::WORD)
        );
        assert_eq!(k.last(), Some(&(K::WORD, "f*")));
        // LOOKUP JOIN reads sources up to ON.
        let k = kinds("FROM a | LOOKUP JOIN idx-*  AS q ON a == b");
        assert_eq!(
            (k[4].0, k[5].0, k[6].0, k[8].0),
            (K::WORD, K::SOURCE_TEXT, K::SOURCE_TEXT, K::WORD)
        );
        assert_eq!(k[9], (K::WORD, "a"));
        // FORK branches are commands.
        let k = kinds("FROM a | FORK (WHERE x | LIMIT 1) (KEEP y*)");
        assert_eq!(k.last().map(|k| k.0), Some(K::R_PAREN));
        assert!(k.contains(&(K::WORD, "y*")));
    }
}
