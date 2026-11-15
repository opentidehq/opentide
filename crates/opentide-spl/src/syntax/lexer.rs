//! The SPL lexer: logos token types driven by a small stage tracker.
//!
//! tree-sitter lexes by the tokens its parser state allows, so the same
//! text splits differently in different places: `a-b` is one field name in
//! `table a-b` and a subtraction in `eval x=a-b`; `foo(bar)` is a call in an
//! aggregate and a word then a group in a search. A logos lexer sees no
//! parser, so this one follows the *stage* instead: which command the
//! current pipeline stage is, and which parentheses are calls. Three token
//! types cover it: [`Search`] (the broad word run, classified by its text),
//! [`Expr`] (eval and where expressions, function arguments) and a raw scan
//! for the contents of `TERM(...)`, `CASE(...)` and `PREFIX(...)`.
//!
//! Every byte is in one lexeme (whitespace and comments are trivia), and a
//! character no token takes is an [`SyntaxKind::ERROR_TOKEN`] of one
//! character. Words are classified by their text only; which words are
//! keywords is the parser's business (`bump_as`).

use super::kind::SyntaxKind as K;
use logos::{Lexer, Logos};
use opentide_parse::Lexeme;
use rowan::{TextRange, TextSize};

/// What a backtick starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tick {
    /// A comment between runs of three or more backticks.
    Comment,
    /// A macro: `` `name` `` or `` `name(args)` ``.
    Macro,
}

/// The length of the comment or macro at the start of `s`, which begins
/// with a backtick. A comment is three or more backticks, a body with no
/// run of three, and a closing run; a macro is a name (`[A-Za-z0-9_]+`),
/// optional arguments in parentheses that may hold anything but a backtick,
/// and a closing backtick.
fn scan_tick(s: &str) -> Option<(Tick, usize)> {
    let bytes = s.as_bytes();
    let run = bytes.iter().take_while(|&&b| b == b'`').count();
    if run >= 3 {
        let mut j = 3;
        while j + 3 <= bytes.len() {
            if &bytes[j..j + 3] == b"```" {
                let end = j + bytes[j..].iter().take_while(|&&b| b == b'`').count();
                return Some((Tick::Comment, end));
            }
            j += 1;
        }
        return None;
    }
    if run != 1 {
        return None;
    }
    let name = bytes[1..]
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
        .count();
    if name == 0 {
        return None;
    }
    let after = 1 + name;
    match bytes.get(after) {
        Some(b'`') => Some((Tick::Macro, after + 1)),
        Some(b'(') => {
            let close = s[after..].find('`')? + after;
            (close > after + 1 && bytes[close - 1] == b')').then_some((Tick::Macro, close + 1))
        }
        _ => None,
    }
}

fn backtick<'s, T: Logos<'s, Source = str>>(lex: &mut Lexer<'s, T>) -> Option<Tick> {
    let start = lex.span().start;
    let (tick, len) = scan_tick(lex.source().get(start..)?)?;
    lex.bump(len - 1);
    Some(tick)
}

/// Words, strings and operators of a search, a command's arguments, and a
/// call's arguments in an aggregate. A word is the broad run of characters
/// that break no term; [`classify`] tells what it is.
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
enum Search {
    #[regex(r"\s+")]
    Whitespace,
    #[token("`", backtick)]
    Backtick(Tick),
    #[regex(r#""([^"\\]|\\[^\n])*""#, priority = 10)]
    #[regex(r"'([^'\\]|\\[^\n])*'", priority = 10)]
    Str,
    #[regex(r#"[^\s"()\[\]|=<>!,`]+"#)]
    Word,
    #[regex(r"[A-Za-z_]+\(\)", priority = 5)]
    CallWord,
    #[token("|")]
    Pipe,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token(",")]
    Comma,
    #[token("=")]
    Eq,
    #[token("==")]
    Eq2,
    #[token("!=")]
    Ne,
    #[token("<")]
    Lt,
    #[token(">")]
    Gt,
    #[token("<=")]
    Le,
    #[token(">=")]
    Ge,
    #[token("<>")]
    LtGt,
    #[token("=>")]
    EqGt,
    #[token("=<")]
    EqLt,
    #[token("!~")]
    BangTilde,
}

/// Eval and where expressions, and the arguments of a call outside an
/// aggregate: names, numbers and operators, each its own token.
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
enum Expr {
    #[regex(r"\s+")]
    Whitespace,
    #[token("`", backtick)]
    Backtick(Tick),
    #[regex(r#""([^"\\]|\\[^\n])*""#)]
    #[regex(r"'([^'\\]|\\[^\n])*'")]
    Str,
    #[regex(r"[A-Za-z_][A-Za-z0-9_:]*(\.[A-Za-z0-9_:]+)*")]
    Ident,
    #[regex(r"[0-9]+(\.[0-9]+)?")]
    Number,
    #[regex(r"[A-Za-z0-9_]*\{[A-Za-z_][A-Za-z0-9_.]*\}[A-Za-z0-9_]*")]
    Dynamic,
    #[regex(r"\$[A-Za-z_][A-Za-z0-9_.:]*\$")]
    TokenName,
    #[regex(r"([A-Za-z0-9_.]|<<[A-Z_0-9]+>>)*<<[A-Z_0-9]+>>([A-Za-z0-9_.]|<<[A-Z_0-9]+>>)*")]
    Template,
    #[token("|")]
    Pipe,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token(",")]
    Comma,
    #[token("=")]
    Eq,
    #[token("==")]
    Eq2,
    #[token("!=")]
    Ne,
    #[token("<")]
    Lt,
    #[token(">")]
    Gt,
    #[token("<=")]
    Le,
    #[token(">=")]
    Ge,
    #[token("!")]
    Bang,
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
    #[token(".")]
    Dot,
}

/// What a word's text is, as the grammar's tokens tell them apart: a name
/// (`identifier`), a number, a field name that is neither, a wildcard, or
/// any other search word. Where the grammar allows more than one, the
/// parser picks (it knows what is valid; tree-sitter's lexer did).
pub(crate) fn classify(word: &str) -> K {
    if word.contains('*') {
        K::GLOB_TOKEN
    } else if is_number(word) {
        K::NUMBER_TOKEN
    } else if is_ident(word) {
        K::IDENT
    } else if is_field_word(word) {
        K::FIELD_WORD
    } else {
        K::SEARCH_WORD_TOKEN
    }
}

fn is_number(word: &str) -> bool {
    let (whole, fraction) = word
        .split_once('.')
        .map_or((word, None), |(a, b)| (a, Some(b)));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    digits(whole) && fraction.is_none_or(digits)
}

fn is_ident(word: &str) -> bool {
    let name = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b':';
    let mut segments = word.split('.');
    let first = segments.next().unwrap_or("");
    let starts = first
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
    starts && first.bytes().all(name) && segments.all(|s| !s.is_empty() && s.bytes().all(name))
}

fn is_field_word(word: &str) -> bool {
    let mut bytes = word.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'@' | b'{'))
        && bytes.all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'_' | b'.' | b':' | b'@' | b'{' | b'}' | b'$' | b'-')
        })
}

/// The length of the raw text of a directive (`TERM(` ...) at the start of
/// `s`: non-space characters up to `)`, with quoted parts allowed to hold
/// anything and an unquoted `|` ending it.
fn term_text_len(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b')' | b'|' => break,
            b'"' => {
                let mut j = i + 1;
                loop {
                    match bytes.get(j) {
                        None => return i,
                        Some(b'"') => break,
                        Some(b'\\') if bytes.get(j + 1).is_some_and(|&b| b != b'\n') => j += 2,
                        Some(b'\\') => return i,
                        Some(_) => j += 1,
                    }
                }
                i = j + 1;
            }
            _ => {
                let c = s[i..].chars().next().map_or(1, char::len_utf8);
                if s[i..].chars().next().is_some_and(char::is_whitespace) {
                    break;
                }
                i += c;
            }
        }
    }
    i
}

/// The length of the option value at the start of `s` that is built from
/// quoted and bare parts with no space between them, read as one argument
/// (`reset_after="("x==\"y\"")"`): any run of quoted strings, escapes and
/// characters that break no argument, with a quoted string or an escape
/// that something follows.
fn compound_len(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let (mut i, mut previous_quoted, mut found) = (0, false, false);
    while i < bytes.len() {
        let (len, quoted) = match bytes[i] {
            b'"' => {
                let mut j = i + 1;
                loop {
                    match bytes.get(j) {
                        None => break,
                        Some(b'"') => break,
                        Some(b'\\') if bytes.get(j + 1).is_some_and(|&b| b != b'\n') => j += 2,
                        Some(b'\\') => break,
                        Some(_) => j += 1,
                    }
                }
                if bytes.get(j) != Some(&b'"') {
                    break;
                }
                (j + 1 - i, true)
            }
            b'\\' => match s[i + 1..].chars().next() {
                Some(c) if c != '\n' => (1 + c.len_utf8(), true),
                _ => break,
            },
            b'|' | b'[' | b']' | b'`' => break,
            _ => match s[i..].chars().next() {
                Some(c) if !c.is_whitespace() => (c.len_utf8(), false),
                _ => break,
            },
        };
        if previous_quoted {
            found = true;
        }
        previous_quoted = quoted;
        i += len;
    }
    found.then_some(i)
}

/// How a stage's tokens are lexed, from its command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// A search: base search, `search`, a subsearch that starts with a
    /// term. Parentheses are groups.
    Search,
    /// `eval` and `where`: expressions throughout.
    Expr,
    /// The stats family and `tstats`: aggregates, whose own arguments are
    /// fields, and whose nested calls take expressions.
    Agg,
    /// Any other command: parentheses after a name are calls.
    Generic,
}

/// A parenthesis that is open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Paren {
    /// A group, or the arguments of an aggregate: words lexed as in a search.
    Search,
    /// The arguments of a call: expressions.
    Expr,
}

/// A pipeline (the query, or one `[ ... ]`).
#[derive(Debug)]
struct Frame {
    /// The next significant token starts a stage.
    at_start: bool,
    /// The stage is the base search (no leading pipe), whatever its first
    /// word.
    bare: bool,
    class: Class,
    spelling: Spelling,
    parens: Vec<Paren>,
    /// The last significant token: its kind, where it ended, and whether it
    /// was a name a call could start with.
    prev: Option<(K, usize)>,
    prev_word: &'static str,
    /// A `TERM(` was opened: the next `)` closes it, and no paren is open.
    directive: bool,
}

impl Frame {
    fn new(bare: bool) -> Self {
        Self {
            at_start: true,
            bare,
            class: Class::Search,
            spelling: Spelling::default(),
            parens: Vec::new(),
            prev: None,
            prev_word: "",
            directive: false,
        }
    }

    /// How the next token is lexed.
    fn mode(&self) -> Paren {
        if self.class == Class::Expr {
            Paren::Expr
        } else {
            self.parens.last().copied().unwrap_or(Paren::Search)
        }
    }
}

/// Words after which `(` opens a group or a list, never a call.
const NOT_CALLS: &[&str] = &[
    "IN",
    "in",
    "notin",
    "AND",
    "OR",
    "NOT",
    "as",
    "by",
    "over",
    "where",
    "from",
    "output",
    "outputnew",
    "and",
    "or",
    "not",
    "sortby",
];

/// The classes of the commands whose spelling decides how the rest of the
/// stage lexes.
fn command_class(word: &str) -> (Class, Spelling) {
    let plain = Spelling::default();
    match word {
        "eval" | "where" => (Class::Expr, plain),
        "search" => (Class::Search, plain),
        "stats" | "eventstats" | "streamstats" | "sistats" | "chart" | "timechart" | "sichart"
        | "sitimechart" | "geostats" | "tstats" => (Class::Agg, plain),
        "fields" | "sort" | "dedup" => (
            Class::Generic,
            Spelling {
                signs: true,
                ..plain
            },
        ),
        "rename" => (
            Class::Generic,
            Spelling {
                prefix_fields: true,
                ..plain
            },
        ),
        _ => (Class::Generic, plain),
    }
}

/// How a command spells its words, beyond its class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Spelling {
    /// `fields`, `sort` and `dedup` take `+` and `-` as signs.
    signs: bool,
    /// `rename` takes tstats's `dst=` as a field name.
    prefix_fields: bool,
}

/// The length of a tstats prefix field (`dst=`, `*=`) at the start of `s`.
fn prefix_field_len(s: &str) -> Option<usize> {
    let name = s
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'*'))
        .count();
    (name > 0 && s.as_bytes().get(name) == Some(&b'=')).then_some(name + 1)
}

/// A `&'static str` for the keywords that matter to the lexer's decisions:
/// the word itself when it is one of them, else `""`.
fn remembered(text: &str) -> &'static str {
    ["TERM", "CASE", "PREFIX"]
        .iter()
        .chain(NOT_CALLS)
        .find(|w| **w == text)
        .copied()
        .unwrap_or("")
}

/// Whether the next significant character of `rest` starts an operator
/// (`=`, `<`, `>`, `!`): the word before it is a field, so the stage is a
/// search, not a command.
fn operator_follows(rest: &str) -> bool {
    rest.starts_with(['=', '<', '>', '!']) || rest.trim_start().starts_with(['=', '!'])
}

struct Driver<'s> {
    source: &'s str,
    frames: Vec<Frame>,
    /// The next significant token is the raw text of a directive.
    raw: bool,
}

impl Driver<'_> {
    fn frame(&mut self) -> &mut Frame {
        let last = self.frames.len() - 1;
        &mut self.frames[last]
    }

    /// The next token at `pos`: its kind and length.
    fn next(&mut self, pos: usize) -> (K, usize) {
        let rest = &self.source[pos..];
        let first_char = rest.chars().next().map_or(1, char::len_utf8);
        if self.raw && !rest.starts_with(char::is_whitespace) {
            self.raw = false;
            let len = term_text_len(rest);
            if len > 0 {
                return (K::TERM_TEXT_TOKEN, len);
            }
        }
        let (mode, class, spelling, after_operator, after_equals) = {
            let f = self.frame();
            let operator = f.prev.is_some_and(|(k, _)| {
                matches!(k, K::EQ | K::EQ2 | K::NE | K::LT | K::GT | K::LE | K::GE)
            });
            let equals = f.prev.is_some_and(|(k, _)| k == K::EQ);
            (f.mode(), f.class, f.spelling, operator, equals)
        };
        match mode {
            Paren::Expr => {
                let mut lexer = Expr::lexer(rest);
                match lexer.next() {
                    Some(Ok(token)) => (expr_kind(token, lexer.slice()), lexer.span().end),
                    _ => (K::ERROR_TOKEN, first_char),
                }
            }
            Paren::Search => {
                if spelling.prefix_fields
                    && let Some(len) = prefix_field_len(rest)
                {
                    return (K::PREFIX_FIELD, len);
                }
                if after_equals
                    && class != Class::Search
                    && let Some(len) = compound_len(rest)
                {
                    return (K::STRING_TOKEN, len);
                }
                let mut lexer = Search::lexer(rest);
                match lexer.next() {
                    Some(Ok(token)) => {
                        let slice = lexer.slice();
                        let len = lexer.span().end;
                        match token {
                            Search::CallWord if class != Class::Search && !after_operator => {
                                // `count()` is a name, `(`, `)`: not a search word.
                                (K::IDENT, len - 2)
                            }
                            Search::CallWord => (K::CALL_WORD, len),
                            Search::Word
                                if spelling.signs && slice.len() > 1 && starts_with_sign(slice) =>
                            {
                                (
                                    if slice.starts_with('+') {
                                        K::PLUS
                                    } else {
                                        K::MINUS
                                    },
                                    1,
                                )
                            }
                            Search::Word if spelling.signs && matches!(slice, "+" | "-") => {
                                (if slice == "+" { K::PLUS } else { K::MINUS }, 1)
                            }
                            _ => (search_kind(token, slice), len),
                        }
                    }
                    _ => (K::ERROR_TOKEN, first_char),
                }
            }
        }
    }

    /// Updates the stage tracker after a significant token.
    fn observe(&mut self, kind: K, start: usize, end: usize) {
        let text = &self.source[start..end];
        let rest = &self.source[end..];
        self.raw = false;
        let mut raw = false;
        let f = self.frame();
        if f.at_start && !matches!(kind, K::PIPE | K::R_BRACKET | K::L_BRACKET) {
            f.at_start = false;
            let named = matches!(
                kind,
                K::IDENT | K::FIELD_WORD | K::NUMBER_TOKEN | K::GLOB_TOKEN | K::SEARCH_WORD_TOKEN
            );
            let (class, spelling) = if f.bare || !named || operator_follows(rest) {
                (Class::Search, Spelling::default())
            } else if kind == K::IDENT {
                command_class(text)
            } else {
                (Class::Generic, Spelling::default())
            };
            f.class = if kind == K::MACRO_TOKEN && !f.bare {
                Class::Search
            } else {
                class
            };
            f.spelling = spelling;
        } else if kind == K::IDENT
            && text.eq_ignore_ascii_case("where")
            && matches!(f.class, Class::Agg | Class::Generic)
        {
            // `tstats ... where` and `inputlookup ... where` take a search.
            f.class = Class::Search;
        }
        match kind {
            K::PIPE => {
                f.at_start = true;
                f.bare = false;
                f.parens.clear();
                f.directive = false;
                f.class = Class::Search;
                f.spelling = Spelling::default();
            }
            K::L_BRACKET => {
                let mut frame = Frame::new(false);
                frame.class = Class::Generic;
                self.frames.push(frame);
                return;
            }
            K::R_BRACKET => {
                if self.frames.len() > 1 {
                    self.frames.pop();
                }
                let f = self.frame();
                f.prev = Some((K::R_BRACKET, end));
                f.prev_word = "";
                return;
            }
            K::L_PAREN => {
                let adjacent_name = f.prev.is_some_and(|(k, e)| k == K::IDENT && e == start);
                if adjacent_name
                    && matches!(f.prev_word, "TERM" | "CASE" | "PREFIX")
                    && f.mode() != Paren::Expr
                {
                    f.directive = true;
                    raw = true;
                } else {
                    let paren = if f.mode() == Paren::Expr {
                        Paren::Expr
                    } else if adjacent_name && !NOT_CALLS.contains(&f.prev_word) {
                        match f.class {
                            Class::Agg if f.parens.is_empty() => Paren::Search,
                            Class::Search => Paren::Search,
                            _ => Paren::Expr,
                        }
                    } else {
                        Paren::Search
                    };
                    f.parens.push(paren);
                }
            }
            K::R_PAREN => {
                if f.directive {
                    f.directive = false;
                } else {
                    f.parens.pop();
                }
            }
            _ => f.directive = false,
        }
        f.prev = Some((kind, end));
        f.prev_word = if kind == K::IDENT {
            remembered(text)
        } else {
            ""
        };
        self.raw = raw;
    }
}

fn starts_with_sign(word: &str) -> bool {
    word.starts_with(['+', '-'])
}

fn search_kind(token: Search, text: &str) -> K {
    match token {
        Search::Whitespace => K::WHITESPACE,
        Search::Backtick(Tick::Comment) => K::COMMENT,
        Search::Backtick(Tick::Macro) => K::MACRO_TOKEN,
        Search::Str => K::STRING_TOKEN,
        Search::Word => classify(text),
        Search::CallWord => K::CALL_WORD,
        Search::Pipe => K::PIPE,
        Search::LBracket => K::L_BRACKET,
        Search::RBracket => K::R_BRACKET,
        Search::LParen => K::L_PAREN,
        Search::RParen => K::R_PAREN,
        Search::Comma => K::COMMA,
        Search::Eq => K::EQ,
        Search::Eq2 => K::EQ2,
        Search::Ne => K::NE,
        Search::Lt => K::LT,
        Search::Gt => K::GT,
        Search::Le => K::LE,
        Search::Ge => K::GE,
        Search::LtGt => K::LT_GT,
        Search::EqGt => K::EQ_GT,
        Search::EqLt => K::EQ_LT,
        Search::BangTilde => K::BANG_TILDE,
    }
}

fn expr_kind(token: Expr, _text: &str) -> K {
    match token {
        Expr::Whitespace => K::WHITESPACE,
        Expr::Backtick(Tick::Comment) => K::COMMENT,
        Expr::Backtick(Tick::Macro) => K::MACRO_TOKEN,
        Expr::Str => K::STRING_TOKEN,
        Expr::Ident => K::IDENT,
        Expr::Number => K::NUMBER_TOKEN,
        Expr::Dynamic => K::DYNAMIC_NAME,
        Expr::TokenName => K::TOKEN_NAME,
        Expr::Template => K::TEMPLATE_NAME,
        Expr::Pipe => K::PIPE,
        Expr::LBracket => K::L_BRACKET,
        Expr::RBracket => K::R_BRACKET,
        Expr::LParen => K::L_PAREN,
        Expr::RParen => K::R_PAREN,
        Expr::Comma => K::COMMA,
        Expr::Eq => K::EQ,
        Expr::Eq2 => K::EQ2,
        Expr::Ne => K::NE,
        Expr::Lt => K::LT,
        Expr::Gt => K::GT,
        Expr::Le => K::LE,
        Expr::Ge => K::GE,
        Expr::Bang => K::BANG,
        Expr::Plus => K::PLUS,
        Expr::Minus => K::MINUS,
        Expr::Star => K::STAR,
        Expr::Slash => K::SLASH,
        Expr::Percent => K::PERCENT,
        Expr::Dot => K::DOT,
    }
}

fn size(n: usize) -> TextSize {
    TextSize::from(u32::try_from(n).unwrap_or(u32::MAX))
}

/// Lexes `source`: lexemes that tile it, in order, trivia included.
pub(crate) fn lex(source: &str) -> Vec<Lexeme> {
    let mut driver = Driver {
        source,
        frames: vec![Frame::new(true)],
        raw: false,
    };
    let mut out = Vec::with_capacity(source.len() / 4 + 1);
    let mut pos = 0;
    while pos < source.len() {
        let (kind, len) = driver.next(pos);
        let len = len.max(1);
        let end = source.ceil_char_boundary(pos + len);
        if !matches!(kind, K::WHITESPACE | K::COMMENT) {
            driver.observe(kind, pos, end);
        }
        out.push(Lexeme {
            kind: kind.raw(),
            range: TextRange::new(size(pos), size(end)),
        });
        pos = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `.spl` file under the test data, with whether it is meant to
    /// parse.
    fn corpus() -> Vec<(std::path::PathBuf, bool)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, bool)>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "spl") {
                    let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
                    let valid =
                        name.is_some_and(|n| !n.contains("__invalid") && !n.contains(".broken."));
                    out.push((path, valid));
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
            &mut out,
        );
        out.sort();
        out
    }

    #[test]
    fn the_corpus_lexes_losslessly_and_a_valid_file_has_no_error_token() {
        let files = corpus();
        assert!(files.len() > 250, "{} files", files.len());
        let mut failures = Vec::new();
        for (path, valid) in &files {
            let source = std::fs::read_to_string(path).expect("read");
            // A corpus fixture's first line is its `prod:` tag, not query text.
            let source = if path.components().any(|c| c.as_os_str() == "corpus") {
                source.lines().skip(1).collect::<Vec<_>>().join("\n")
            } else {
                source
            };
            let lexemes = lex(&source);
            let mut end = 0usize;
            for l in &lexemes {
                assert_eq!(usize::from(l.range.start()), end, "{}", path.display());
                end = usize::from(l.range.end());
            }
            assert_eq!(end, source.len(), "{}", path.display());
            if *valid {
                for l in lexemes.iter().filter(|l| l.kind == K::ERROR_TOKEN.raw()) {
                    let at = usize::from(l.range.start());
                    failures.push(format!(
                        "{}: error token {:?} near {:?}",
                        path.display(),
                        &source[std::ops::Range::<usize>::from(l.range)],
                        &source[at.saturating_sub(20)..source.len().min(at + 20)]
                    ));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    fn kinds(source: &str) -> Vec<(K, &str)> {
        lex(source)
            .iter()
            .filter(|l| l.kind != K::WHITESPACE.raw())
            .map(|l| {
                let kind = <crate::syntax::kind::Lang as rowan::Language>::kind_from_raw(l.kind);
                (kind, &source[std::ops::Range::<usize>::from(l.range)])
            })
            .collect()
    }

    /// The byte ranges of the tree-sitter tree's leaves.
    fn leaves(node: tree_sitter::Node<'_>, out: &mut Vec<(usize, usize)>) {
        if node.child_count() == 0 {
            if node.end_byte() > node.start_byte() {
                out.push((node.start_byte(), node.end_byte()));
            }
            return;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            leaves(child, out);
        }
    }

    /// Where the old lexer put its token boundaries, the new one puts them,
    /// on every file the old parser accepts. The known exceptions are
    /// tokens the grammar glues from more than one of ours (the parser
    /// does it): see `NOTES.md`.
    #[test]
    fn tokens_start_and_end_where_tree_sitters_do() {
        let mut mismatches = Vec::new();
        let (mut files, mut tokens) = (0, 0);
        for (path, valid) in corpus() {
            if !valid {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read");
            let source = if path.components().any(|c| c.as_os_str() == "corpus") {
                source.lines().skip(1).collect::<Vec<_>>().join("\n")
            } else {
                source
            };
            let Some(tree) = opentide_syntax::parse(opentide_core::LanguageId::Spl, &source) else {
                continue;
            };
            if opentide_syntax::has_error(&tree) {
                continue;
            }
            files += 1;
            let mut old = Vec::new();
            leaves(tree.root_node(), &mut old);
            let new: Vec<(usize, usize)> = lex(&source)
                .iter()
                .filter(|l| l.kind != K::WHITESPACE.raw())
                .map(|l| (usize::from(l.range.start()), usize::from(l.range.end())))
                .collect();
            tokens += old.len();
            if old != new {
                let at = old
                    .iter()
                    .zip(&new)
                    .position(|(a, b)| a != b)
                    .unwrap_or(old.len().min(new.len()));
                let show = |v: &[(usize, usize)]| {
                    v.get(at)
                        .map_or(String::from("-"), |&(a, b)| format!("{:?}", &source[a..b]))
                };
                mismatches.push(format!(
                    "{}: token {at}: tree-sitter {}, here {}",
                    path.display(),
                    show(&old),
                    show(&new)
                ));
            }
        }
        assert!(files > 150, "{files} files compared");
        assert!(
            mismatches.is_empty(),
            "{} of {files} files ({tokens} tokens) differ:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }

    #[test]
    fn a_search_is_words_and_operators() {
        assert_eq!(
            kinds("index=main user!=bob*"),
            vec![
                (K::IDENT, "index"),
                (K::EQ, "="),
                (K::IDENT, "main"),
                (K::IDENT, "user"),
                (K::NE, "!="),
                (K::GLOB_TOKEN, "bob*"),
            ]
        );
    }

    #[test]
    fn eval_splits_names_a_command_argument_keeps() {
        assert_eq!(
            kinds("| eval x=a-b"),
            vec![
                (K::PIPE, "|"),
                (K::IDENT, "eval"),
                (K::IDENT, "x"),
                (K::EQ, "="),
                (K::IDENT, "a"),
                (K::MINUS, "-"),
                (K::IDENT, "b"),
            ]
        );
        assert_eq!(
            kinds("| table a-b")[2],
            (K::FIELD_WORD, "a-b"),
            "a field name keeps its dash outside eval"
        );
    }

    #[test]
    fn a_call_in_an_aggregate_takes_expressions_below_the_top() {
        let tokens = kinds("| stats sum(a-b) as s, count(eval(x-1))");
        assert!(tokens.contains(&(K::FIELD_WORD, "a-b")), "{tokens:?}");
        assert!(tokens.contains(&(K::MINUS, "-")), "{tokens:?}");
    }

    #[test]
    fn a_subsearch_is_a_stage_of_its_own() {
        let tokens = kinds("| eval a=1 | search x=[ search b-c ]");
        assert!(tokens.contains(&(K::FIELD_WORD, "b-c")), "{tokens:?}");
        let tokens = kinds("| where [ | inputlookup t.csv ] | table a-b");
        assert!(tokens.contains(&(K::FIELD_WORD, "a-b")), "{tokens:?}");
    }

    #[test]
    fn comments_macros_and_strings() {
        assert_eq!(
            kinds("```c ` ``` `m(1)` \"a\\\"b\" 'c' `x`"),
            vec![
                (K::COMMENT, "```c ` ```"),
                (K::MACRO_TOKEN, "`m(1)`"),
                (K::STRING_TOKEN, "\"a\\\"b\""),
                (K::STRING_TOKEN, "'c'"),
                (K::MACRO_TOKEN, "`x`"),
            ]
        );
        assert_eq!(kinds("\"open")[0].0, K::ERROR_TOKEN);
        assert_eq!(kinds("``x`")[0].0, K::ERROR_TOKEN);
    }

    #[test]
    fn a_directive_takes_raw_text() {
        let tokens = kinds("TERM(EventID=4688) x=1");
        assert_eq!(
            tokens[..4],
            [
                (K::IDENT, "TERM"),
                (K::L_PAREN, "("),
                (K::TERM_TEXT_TOKEN, "EventID=4688"),
                (K::R_PAREN, ")"),
            ]
        );
        assert_eq!(tokens[4], (K::IDENT, "x"), "the group stack is balanced");
        let open = kinds("TERM(a b");
        assert_eq!(open[2], (K::TERM_TEXT_TOKEN, "a"));
        assert_eq!(open[3], (K::IDENT, "b"));
    }

    #[test]
    fn signs_split_in_fields_and_sort() {
        let tokens = kinds("| sort -lt, +x");
        assert_eq!(tokens[2], (K::MINUS, "-"));
        assert_eq!(tokens[3], (K::IDENT, "lt"));
        assert_eq!(kinds("| fields - a")[2], (K::MINUS, "-"));
        assert_eq!(kinds("earliest=-1h@h")[2], (K::SEARCH_WORD_TOKEN, "-1h@h"));
    }

    /// A prefix cuts a string, a macro, a comment or a directive anywhere:
    /// the lexemes still tile it, and nothing panics.
    #[test]
    fn every_prefix_of_a_file_lexes_losslessly() {
        for (path, _) in corpus().iter().step_by(5) {
            let source = std::fs::read_to_string(path).expect("read");
            let mut end = 0;
            while end < source.len().min(600) {
                end = source.ceil_char_boundary(end + 3);
                let prefix = &source[..end.min(source.len())];
                let covered: usize = lex(prefix)
                    .iter()
                    .map(|l| usize::from(l.range.end() - l.range.start()))
                    .sum();
                assert_eq!(covered, prefix.len(), "{}: {prefix:?}", path.display());
            }
        }
    }

    #[test]
    fn every_byte_is_in_a_lexeme() {
        for source in [
            "",
            "|",
            "a \u{a0}\u{3000}b",
            "x=\"é\" `m` ```",
            "[[[ ((( ]]] )))",
            "| eval {f}=<<FIELD>> + $tok$",
            "TERM(\"a",
        ] {
            let lexemes = lex(source);
            let mut end = 0usize;
            for l in &lexemes {
                assert_eq!(usize::from(l.range.start()), end, "{source:?}");
                end = usize::from(l.range.end());
                assert!(source.is_char_boundary(end), "{source:?}");
            }
            assert_eq!(end, source.len(), "{source:?}");
        }
    }
}
