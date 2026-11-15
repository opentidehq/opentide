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
    /// Where a command starts: its first word is read whole.
    Start,
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
    /// `FORK` and `EXPLAIN`: every `(` opens a query.
    Branching,
}

#[derive(Clone, Copy, Debug)]
struct Frame {
    mode: Mode,
    cmd: Cmd,
}

const START: Frame = Frame {
    mode: Mode::Start,
    cmd: Cmd::Other,
};

/// The mode and flavour of the operands of the command that starts with
/// `word` (lower case); `None` for a command the grammar does not know.
fn mode_of(word: &str) -> Option<Frame> {
    let frame = |mode, cmd| Some(Frame { mode, cmd });
    match word {
        "from" | "ts" => frame(Mode::Source, Cmd::Other),
        "keep" | "drop" | "rename" => frame(Mode::Names, Cmd::Other),
        "enrich" => frame(Mode::Policy, Cmd::Enrich),
        "lookup" | "left" | "right" | "full" => frame(Mode::JoinKw, Cmd::Other),
        "promql" => frame(Mode::Promql, Cmd::Other),
        "fork" | "explain" => frame(Mode::Expr, Cmd::Branching),
        "highlight" => frame(Mode::Expr, Cmd::Highlight),
        "fillnull" => frame(Mode::Expr, Cmd::FillNull),
        "row" | "show" | "set" | "where" | "eval" | "sort" | "limit" | "stats" | "inline"
        | "inlinestats" | "dissect" | "grok" | "mv_expand" | "change_point" | "completion"
        | "rerank" | "sample" | "fuse" | "uri_parts" | "registered_domain" | "user_agent"
        | "ip_location" | "metrics_info" | "ts_info" | "ts_collapse" | "dedup" | "mmr"
        | "dense_vector" => frame(Mode::Expr, Cmd::Other),
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
fn block_comment(rest: &str) -> Option<usize> {
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
}

impl Driver<'_> {
    /// The next token's kind and length.
    fn token(&self) -> (K, usize) {
        let rest = &self.source[self.pos..];
        let spaces = take(rest, char::is_whitespace);
        if spaces > 0 {
            return (K::WHITESPACE, spaces);
        }
        if rest.starts_with("//") {
            return (K::COMMENT, rest.find(['\r', '\n']).unwrap_or(rest.len()));
        }
        if rest.starts_with("/*")
            && let Some(len) = block_comment(rest)
        {
            return (K::COMMENT, len);
        }
        if rest.starts_with('"')
            && let Some(len) = string(rest)
        {
            return (K::STRING_LIT, len);
        }
        let (text_kind, len) = match self.frame.mode {
            Mode::Start => (
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
                (tok.kind(), len)
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
            K::PIPE => self.set(START),
            K::SEMI if self.stack.is_empty() => self.set(START),
            K::L_PAREN => self.open(was_in),
            K::R_PAREN => {
                if let Some(frame) = self.stack.pop() {
                    self.set(frame);
                }
            }
            K::COMMAND_WORD if mode == Mode::Start => match mode_of(&text.to_ascii_lowercase()) {
                Some(frame) => {
                    kind = K::WORD;
                    self.set(frame);
                }
                None => self.set(Frame {
                    mode: Mode::Unknown,
                    cmd: Cmd::Other,
                }),
            },
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
            (Mode::Source, _) | (_, Cmd::Branching) => true,
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
            self.set(START);
        }
    }
}

/// The lexemes of `source`: they tile it, trivia included.
pub(crate) fn lex(source: &str) -> Vec<Lexeme> {
    let mut driver = Driver {
        source,
        pos: 0,
        frame: START,
        stack: Vec::new(),
        seen: 0,
        after_in: false,
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
    use std::path::{Path, PathBuf};

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

    /// Every `.esql` file under `crates/testdata`.
    fn corpus() -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "esql") {
                    out.push(path);
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
            &mut out,
        );
        out.sort();
        out
    }

    #[test]
    fn lexemes_tile_every_corpus_file_and_valid_ones_have_no_error_token() {
        let files = corpus();
        assert!(files.len() > 150, "found {} corpus files", files.len());
        for path in files {
            let source = std::fs::read_to_string(&path).unwrap_or_default();
            let lexemes = lex(&source);
            let text: String = lexemes
                .iter()
                .map(|l| &source[std::ops::Range::<usize>::from(l.range)])
                .collect();
            assert_eq!(text, source, "{} is not tiled", path.display());
            let name = path.to_string_lossy();
            let broken = name.contains("__invalid") || name.contains(".broken.");
            let errors = lexemes
                .iter()
                .filter(|l| l.kind == K::ERROR_TOKEN.raw())
                .count();
            assert!(broken || errors == 0, "{name}: {errors} error tokens");
        }
    }

    /// The leaves of the tree-sitter tree (what its context-aware lexer
    /// read), as byte ranges.
    fn tree_sitter_leaves(source: &str) -> Vec<(usize, usize)> {
        let tree = opentide_syntax::parse(opentide_core::LanguageId::Esql, source).unwrap();
        let mut out = Vec::new();
        opentide_syntax::walk(tree.root_node(), |node| {
            if node.child_count() == 0 && node.end_byte() > node.start_byte() {
                out.push((node.start_byte(), node.end_byte()));
            }
        });
        out
    }

    /// The modes reproduce what tree-sitter's lexer read, token for token,
    /// on every corpus file it parses without an error.
    #[test]
    fn tokens_are_the_leaves_tree_sitter_read() {
        let mut compared = 0;
        for path in corpus() {
            let source = std::fs::read_to_string(&path).unwrap_or_default();
            let root = opentide_syntax::parse(opentide_core::LanguageId::Esql, &source).unwrap();
            if opentide_syntax::first_error(root.root_node()).is_some() {
                continue;
            }
            let ours: Vec<_> = lex(&source)
                .iter()
                .filter(|l| l.kind != K::WHITESPACE.raw())
                .map(|l| (usize::from(l.range.start()), usize::from(l.range.end())))
                .collect();
            assert_eq!(ours, tree_sitter_leaves(&source), "{}", path.display());
            compared += 1;
        }
        assert!(compared > 120, "compared {compared} files");
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
        assert_eq!(kinds("EVAL /* a /* b")[1], (K::SLASH, "/"));
        assert_eq!(kinds("EVAL /* a */ */").last(), Some(&(K::SLASH, "/")));
    }

    #[test]
    fn strings_and_quoted_identifiers() {
        let k = |s: &str| {
            let source = format!("EVAL {s}");
            let (kind, text) = kinds(&source)[1];
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
            assert_eq!(kinds(&format!("eval {text}"))[1], (K::NUMBER_LIT, text));
        }
        let parts = kinds("eval 1e");
        assert_eq!((parts[1], parts[2]), ((K::NUMBER_LIT, "1"), (K::WORD, "e")));
        assert_eq!(kinds("eval ??a, ?1, ?")[1].0, K::PARAM);
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
            kinds("EVAL a*b")[1..]
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
    fn modes_follow_subqueries_policies_and_joins() {
        // A subquery is a query again, then the list goes on.
        let k = kinds("FROM a, (FROM b | WHERE x) METADATA _id");
        assert_eq!(k.last(), Some(&(K::SOURCE_TEXT, "_id")));
        assert_eq!(k[7], (K::WORD, "WHERE"));
        // `IN (FROM ...)` is a subquery; `IN (a, b)` is not.
        assert_eq!(kinds("EVAL x IN (FROM b)")[4], (K::WORD, "FROM"));
        assert_eq!(kinds("EVAL x IN (a, from)")[4], (K::WORD, "a"));
        assert_eq!(kinds("WHERE x IN (from_a)")[4], (K::WORD, "from_a"));
        // ENRICH reads a policy name, then name patterns.
        let k = kinds("ENRICH ctx:on_policy ON a* WITH n = f*");
        assert_eq!(
            (k[1].0, k[3].0, k[4].0, k[5].0),
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
