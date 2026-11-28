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
            let close = bytes[after..].iter().position(|b| *b == b'`')? + after;
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

/// The dotted segments of a name (`a.b.c`): a callback, because logos'
/// generated code for a repeated group recurses once per repetition and
/// aborts the process on a long token.
fn ident_tail(lex: &mut Lexer<'_, Expr>) {
    loop {
        let rest = lex.remainder().as_bytes();
        if rest.first() != Some(&b'.') {
            return;
        }
        let segment = rest[1..]
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_' || **c == b':')
            .count();
        if segment == 0 {
            return;
        }
        lex.bump(1 + segment);
    }
}

/// The length of the string at the start of `s`, quoted with `"` or `'`
/// (a backslash escapes any character but a line break), or `None` when it
/// is not closed. In a search a `'` string that a word continues
/// (`'ab'cd`) is that word, as the longest match was in the old lexer.
fn string_len(s: &str, in_search: bool, dead: &mut [bool; 2]) -> Option<usize> {
    let bytes = s.as_bytes();
    let quote = *bytes.first()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    // A scan that found no closing quote would find none from any later
    // quote of the same kind either (it ends in the same state), so it is
    // not repeated: a source of unclosed quotes stays linear.
    let kind = usize::from(quote == b'\'');
    if dead[kind] {
        return None;
    }
    let mut i = 1;
    let end = loop {
        match bytes.get(i) {
            None => {
                dead[kind] = true;
                return None;
            }
            Some(b'\\') => match bytes.get(i + 1) {
                Some(&c) if c != b'\n' => i += 2,
                None => {
                    dead[kind] = true;
                    return None;
                }
                // A line break after the backslash ends this string only: a
                // later quote may close.
                Some(_) => return None,
            },
            Some(&c) if c == quote => break i + 1,
            Some(_) => i += 1,
        }
    };
    if quote == b'\'' && in_search {
        let next = s.get(end..)?.chars().next();
        if next.is_some_and(|c| !c.is_whitespace() && !"\"()[]|=<>!,`".contains(c)) {
            return None;
        }
    }
    Some(end)
}

/// The length of a call word (`now()`) at the start of `s`.
fn callword_len(s: &str) -> Option<usize> {
    let rest = s.trim_start_matches(|c: char| c.is_ascii_alphabetic() || c == '_');
    let name = s.len() - rest.len();
    (name > 0 && rest.starts_with("()")).then_some(name + 2)
}

/// The length of the identifier at the start of `s`: a name, then dotted
/// segments (`alert.attack`), as `grammar.js` spells `identifier`.
fn ident_len(s: &str) -> Option<usize> {
    let name = |b: &u8| b.is_ascii_alphanumeric() || *b == b'_' || *b == b':';
    let bytes = s.as_bytes();
    if !bytes
        .first()
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return None;
    }
    let mut i = bytes.iter().take_while(|b| name(b)).count();
    while bytes.get(i) == Some(&b'.') {
        let segment = bytes[i + 1..].iter().take_while(|b| name(b)).count();
        if segment == 0 {
            break;
        }
        i += 1 + segment;
    }
    Some(i)
}

/// The length of the `foreach` template at the start of `s`: name
/// characters and `<<FIELD>>` markers, at least one marker.
fn template_len(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let (mut i, mut seen) = (0, false);
    loop {
        if bytes[i..].starts_with(b"<<") {
            let name = bytes[i + 2..]
                .iter()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || **c == b'_')
                .count();
            if name > 0 && bytes[i + 2 + name..].starts_with(b">>") {
                i += name + 4;
                seen = true;
                continue;
            }
            break;
        }
        match bytes.get(i) {
            Some(c) if c.is_ascii_alphanumeric() || *c == b'_' || *c == b'.' => i += 1,
            _ => break,
        }
    }
    seen.then_some(i)
}

/// The rest of a run of white space (a callback: logos' generated code for a
/// repeated class recurses once per character of a multibyte run, and aborts
/// the process on a long one).
fn space_tail<'s, T: Logos<'s, Source = str>>(lex: &mut Lexer<'s, T>) {
    let n = lex
        .remainder()
        .find(|c: char| !c.is_whitespace())
        .unwrap_or(lex.remainder().len());
    lex.bump(n);
}

/// The rest of a search word: characters up to white space or an operator,
/// bracket, quote or backtick (a callback, as [`space_tail`]).
fn word_tail<'s, T: Logos<'s, Source = str>>(lex: &mut Lexer<'s, T>) {
    let n = lex
        .remainder()
        .find(|c: char| c.is_whitespace() || "\"()[]|=<>!,`".contains(c))
        .unwrap_or(lex.remainder().len());
    lex.bump(n);
}

/// Words, strings and operators of a search, a command's arguments, and a
/// call's arguments in an aggregate. A word is the broad run of characters
/// that break no term; [`classify`] tells what it is.
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
enum Search {
    #[regex(r"\s", space_tail)]
    Whitespace,
    #[token("`", backtick)]
    Backtick(Tick),
    #[regex(r#"[^\s"()\[\]|=<>!,`]"#, word_tail)]
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
    #[regex(r"\s", space_tail)]
    Whitespace,
    #[token("`", backtick)]
    Backtick(Tick),
    #[regex(r"[A-Za-z_][A-Za-z0-9_:]*", ident_tail)]
    Ident,
    #[regex(r"[0-9]+(\.[0-9]+)?")]
    Number,
    #[regex(r"[A-Za-z0-9_]*\{[A-Za-z_][A-Za-z0-9_.]*\}[A-Za-z0-9_]*")]
    Dynamic,
    #[regex(r"\$[A-Za-z_][A-Za-z0-9_.:]*\$")]
    TokenName,
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
                #[expect(
                    clippy::string_slice,
                    reason = "`i` moves past whole characters, or to just after an ASCII \
                              quote: a char boundary"
                )]
                let rest = &s[i..];
                match rest.chars().next() {
                    Some(c) if !c.is_whitespace() => i += c.len_utf8(),
                    _ => break,
                }
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
///
/// Returns the length (when there is a compound), how far the scan went, and
/// whether it met a quoted part or an escape: with none, no start before the
/// end of the scan can make a compound either, which lets the caller skip
/// them (a run of `a=a=a=` stays linear).
fn compound_len(s: &str) -> (Option<usize>, usize, bool) {
    let bytes = s.as_bytes();
    let (mut i, mut previous_quoted, mut found, mut quoted_any) = (0, false, false, false);
    while i < bytes.len() {
        #[expect(
            clippy::string_slice,
            reason = "`i` moves past whole characters, escapes of one, or quoted runs that \
                      end at an ASCII quote: a char boundary"
        )]
        let rest = &s[i..];
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
            b'\\' => match rest.chars().nth(1) {
                Some(c) if c != '\n' => (1 + c.len_utf8(), true),
                _ => break,
            },
            b'|' | b'[' | b']' | b'`' => break,
            _ => match rest.chars().next() {
                Some(c) if !c.is_whitespace() => (c.len_utf8(), false),
                _ => break,
            },
        };
        if previous_quoted {
            found = true;
        }
        previous_quoted = quoted;
        quoted_any |= quoted;
        i += len;
    }
    (found.then_some(i), i, quoted_any)
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
    /// The list after `IN` in an expression: search values.
    List,
}

/// A pipeline (the query, or one `[ ... ]`).
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent flags of the lexer's stage state, each read alone"
)]
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
    /// The last name followed a comparison operator (`a=TERM(`): then it is
    /// a value, and its parenthesis a group, not a directive.
    name_after_operator: bool,
    /// The stage is a stats-family command: after `where`, `by` returns to
    /// aggregate lexing.
    agg: bool,
    /// The `by` clause began: a later `where` is a name.
    after_by: bool,
    /// The token just before was the keyword `where` of a tstats.
    after_where: bool,
    /// Significant tokens since the command word (`by` is an aggregate first).
    stage_tokens: u32,
}

impl Frame {
    fn new(bare: bool) -> Self {
        Self {
            at_start: true,
            bare,
            class: Class::Search,
            spelling: Spelling::default(),
            parens: Vec::new(),
            name_after_operator: false,
            agg: false,
            after_by: false,
            after_where: false,
            stage_tokens: 0,
            prev: None,
            prev_word: "",
            directive: false,
        }
    }

    /// How the next token is lexed.
    fn mode(&self) -> Paren {
        match (self.class, self.parens.last()) {
            // `x IN (a-b, c*)` in an expression lists search values.
            (_, Some(Paren::List)) => Paren::Search,
            (Class::Expr, _) => Paren::Expr,
            (_, top) => top.copied().unwrap_or(Paren::Search),
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
        | "sitimechart" | "geostats" => (Class::Agg, plain),
        "tstats" => (
            Class::Agg,
            Spelling {
                search_where: true,
                ..plain
            },
        ),
        "fields" | "sort" | "dedup" => (
            Class::Generic,
            Spelling {
                signs: true,
                narrow_words: true,
                ..plain
            },
        ),
        "rename" => (
            Class::Generic,
            Spelling {
                prefix_fields: true,
                narrow_words: true,
                ..plain
            },
        ),
        "inputlookup" => (
            Class::Generic,
            Spelling {
                narrow_words: true,
                search_where: true,
                ..plain
            },
        ),
        "table" | "rex" | "fillnull" | "mvexpand" | "makemv" | "join" | "lookup"
        | "outputlookup" | "foreach" | "spath" | "tojson" | "head" | "tail" => (
            Class::Generic,
            Spelling {
                narrow_words: true,
                ..plain
            },
        ),
        _ => (
            Class::Generic,
            Spelling {
                call_words: true,
                ..plain
            },
        ),
    }
}

/// How a command spells its words, beyond its class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent flags of the lexer's stage state, each read alone"
)]
struct Spelling {
    /// `fields`, `sort` and `dedup` take `+` and `-` as signs.
    signs: bool,
    /// `rename` takes tstats's `dst=` as a field name.
    prefix_fields: bool,
    /// A command with no rule of its own takes `now()` as one search word.
    call_words: bool,
    /// A command that takes names only: a word stops at a quote (`a'b'`).
    narrow_words: bool,
    /// `where` starts a search (tstats, inputlookup); elsewhere it is a name.
    search_where: bool,
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
    /// Whether an unclosed `"` or `'` was met: no later one closes.
    dead_quotes: [bool; 2],
    /// No compound value starts before this offset (a scan found no quote).
    no_compound_until: usize,
}

impl Driver<'_> {
    fn frame(&mut self) -> &mut Frame {
        let last = self.frames.len() - 1;
        &mut self.frames[last]
    }

    /// The next token at `pos`: its kind and length.
    fn next(&mut self, pos: usize) -> (K, usize) {
        #[expect(
            clippy::string_slice,
            reason = "`pos` is the end of the tokens before it, each a whole number of characters"
        )]
        let rest = &self.source[pos..];
        let first_char = rest.chars().next().map_or(1, char::len_utf8);
        // A comment, or a macro no longer than the text, takes the place of
        // the raw text of a directive (`TERM(`m(1)` x`).
        let tick = scan_tick(rest);
        let tick_wins = match tick {
            Some((Tick::Comment, _)) => true,
            Some((Tick::Macro, len)) => len >= term_text_len(rest),
            None => false,
        };
        if self.raw && !rest.starts_with(char::is_whitespace) && !tick_wins {
            self.raw = false;
            let len = term_text_len(rest);
            // `CASE(Admin()`: the call word `Admin()` is longer than the text.
            let call = callword_len(rest).unwrap_or(0);
            // `CASE((x)`: a lone `(` or `[` is the token, not the text.
            let lone = len == 1
                && (matches!(rest.as_bytes()[0], b'(' | b'[')
                    || (rest.as_bytes()[0] == b']' && self.frames.len() > 1));
            if len > 0 && call <= len && !lone {
                return (K::TERM_TEXT_TOKEN, len);
            }
        }
        let command_position = {
            let f = self.frame();
            f.at_start && !f.bare && f.prev.is_some_and(|(k, _)| k == K::PIPE)
        };
        if command_position && let Some(len) = ident_len(rest) {
            // tree-sitter reads the command word as an identifier here, where
            // only a command (or a macro) can start: `fields{` is `fields`
            // then `{`, `a{}.b` is `a` then `{}.b`.
            return (K::IDENT, len);
        }
        let (mode, class, spelling, after_operator, after_equals, at_start) = {
            let f = self.frame();
            let operator = f.prev.is_some_and(|(k, _)| {
                matches!(k, K::EQ | K::EQ2 | K::NE | K::LT | K::GT | K::LE | K::GE)
            });
            let equals = f
                .prev
                .is_some_and(|(k, _)| matches!(k, K::EQ | K::NE | K::LT | K::GT | K::LE | K::GE));
            (f.mode(), f.class, f.spelling, operator, equals, f.at_start)
        };
        match mode {
            Paren::Expr => {
                if let Some(len) = string_len(rest, false, &mut self.dead_quotes) {
                    return (K::STRING_TOKEN, len);
                }
                let mut lexer = Expr::lexer(rest);
                match lexer.next() {
                    Some(Ok(token)) => {
                        let len = lexer.span().end;
                        match template_len(rest) {
                            Some(t) if t >= len => (K::TEMPLATE_NAME, t),
                            _ => (expr_kind(token), len),
                        }
                    }
                    _ => (K::ERROR_TOKEN, first_char),
                }
            }
            Paren::Search | Paren::List => {
                if spelling.prefix_fields
                    && let Some(len) = prefix_field_len(rest)
                {
                    return (K::PREFIX_FIELD, len);
                }
                if after_equals && class != Class::Search && pos >= self.no_compound_until {
                    let (found, scanned, quoted) = compound_len(rest);
                    if let Some(len) = found {
                        return (K::STRING_TOKEN, len);
                    }
                    if !quoted {
                        self.no_compound_until = pos + scanned;
                    }
                }
                if let Some(len) = string_len(rest, true, &mut self.dead_quotes) {
                    return (K::STRING_TOKEN, len);
                }
                if class != Class::Search && !at_start {
                    // The loose comparisons are a search's: here `==` is `=` and
                    // `=`, `<>` is `<` and `>`.
                    if rest.starts_with("==") || rest.starts_with("=>") || rest.starts_with("=<") {
                        return (K::EQ, 1);
                    }
                    if rest.starts_with("<>") {
                        return (K::LT, 1);
                    }
                }
                let mut lexer = Search::lexer(rest);
                match lexer.next() {
                    Some(Ok(token)) => {
                        let slice = lexer.slice();
                        let len = lexer.span().end;
                        match token {
                            Search::CallWord
                                if class != Class::Search
                                    && !after_operator
                                    && !spelling.call_words =>
                            {
                                // `count()` is a name, `(`, `)`: not a search word.
                                (K::IDENT, len - 2)
                            }
                            Search::CallWord => (K::CALL_WORD, len),
                            Search::Word
                                if spelling.narrow_words
                                    && slice.contains('\'')
                                    && !slice.contains('*') =>
                            {
                                // At the `'`, or past it when it comes first.
                                let (head, _) = slice.split_once('\'').unwrap_or((slice, ""));
                                let head = if head.is_empty() { "'" } else { head };
                                (classify(head), head.len())
                            }
                            Search::Word
                                if spelling.signs
                                    && !starts_with_sign(slice)
                                    && after_first(slice).contains('+') =>
                            {
                                // After the first character, which can be any
                                // character: `slice[1..]` cut inside `\u{70f}`.
                                let tail = after_first(slice);
                                let plus = tail.find('+').unwrap_or(0);
                                let cut = slice.len() - tail.len() + plus;
                                #[expect(
                                    clippy::string_slice,
                                    reason = "`cut` is the end of the first character plus the \
                                              offset of a `+` after it: a char boundary"
                                )]
                                let head = &slice[..cut];
                                (classify(head), cut)
                            }
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
        #[expect(
            clippy::string_slice,
            reason = "`start..end` is a token's span, which `next` cuts at char boundaries"
        )]
        let (text, rest) = (&self.source[start..end], &self.source[end..]);
        self.raw = false;
        let mut raw = false;
        let f = self.frame();
        if f.at_start && !matches!(kind, K::PIPE | K::R_BRACKET | K::L_BRACKET) {
            f.at_start = false;
            let named = matches!(
                kind,
                K::IDENT | K::FIELD_WORD | K::NUMBER_TOKEN | K::GLOB_TOKEN | K::SEARCH_WORD_TOKEN
            );
            // A stage starts as a search unless a plain name begins a command: a
            // directive (`TERM(`), a field word or a number can only begin terms.
            let (class, spelling) =
                if f.bare || !named || operator_follows(rest) || matches!(text, "TERM" | "CASE") {
                    (Class::Search, Spelling::default())
                } else if kind == K::IDENT {
                    command_class(text)
                } else {
                    (Class::Search, Spelling::default())
                };
            f.class = if kind == K::MACRO_TOKEN && !f.bare {
                Class::Search
            } else {
                class
            };
            f.spelling = spelling;
            f.agg = class == Class::Agg;
            f.stage_tokens = 0;
            f.after_where = false;
        } else if kind == K::IDENT
            && text.eq_ignore_ascii_case("by")
            && f.agg
            && f.parens.is_empty()
            // `by` is the clause once an aggregate precedes it, not a term after
            // `where`, `AND`, `as` or an operator, nor an aggregate after a comma.
            && f.stage_tokens >= 2
            && !f.after_where
            && !matches!(f.prev_word, "AND" | "OR" | "NOT")
            && !(f.prev_word == "as" && f.class != Class::Search)
            && !f.prev.is_some_and(|(k, _)| {
                matches!(k, K::COMMA | K::EQ | K::NE | K::LT | K::GT | K::LE | K::GE)
            })
        {
            f.class = Class::Agg;
            f.after_by = true;
        } else if kind == K::IDENT
            && text.eq_ignore_ascii_case("where")
            && f.spelling.search_where
            && !f.after_by
            && matches!(f.class, Class::Agg | Class::Generic)
        {
            // `tstats ... where` and `inputlookup ... where` take a search.
            f.class = Class::Search;
            f.spelling = Spelling::default();
            f.after_where = true;
            f.stage_tokens += 1;
            f.prev = Some((kind, end));
            f.prev_word = "where";
            return;
        }
        match kind {
            K::PIPE => {
                f.after_by = false;
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
                let name = f.prev.is_some_and(|(k, _)| k == K::IDENT);
                // In a search `a (b)` is a term and a group; elsewhere a name and
                // its parenthesis are a call, space or not.
                let adjacent_name = f.prev.is_some_and(|(k, e)| {
                    k == K::IDENT && (e == start || f.class != Class::Search)
                });
                let searching = f.class == Class::Search;
                let directive = match f.prev_word {
                    "TERM" | "CASE" => searching,
                    "PREFIX" => !searching,
                    _ => false,
                };
                if name && directive && f.mode() != Paren::Expr && !f.name_after_operator {
                    f.directive = true;
                    raw = true;
                } else {
                    let paren = if f.prev_word == "IN" && f.mode() == Paren::Expr {
                        Paren::List
                    } else if f.mode() == Paren::Expr {
                        Paren::Expr
                    } else if adjacent_name
                        && !(if f.class == Class::Generic {
                            // Args of a command with no rule: only these are never calls.
                            matches!(f.prev_word, "AND" | "OR" | "NOT" | "IN")
                        } else {
                            NOT_CALLS.contains(&f.prev_word)
                        })
                    {
                        match f.class {
                            // The call of an option value (`x=if(a, b)`) takes expressions.
                            Class::Agg if f.parens.is_empty() && !f.name_after_operator => {
                                Paren::Search
                            }
                            Class::Search => Paren::Search,
                            _ => Paren::Expr,
                        }
                    } else {
                        Paren::Search
                    };
                    f.directive = false;
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
        f.after_where = false;
        // A macro stands for anything: it does not make `by` a clause.
        if kind != K::MACRO_TOKEN {
            f.stage_tokens += 1;
        }
        f.name_after_operator = kind == K::IDENT
            && f.prev
                .is_some_and(|(k, _)| matches!(k, K::EQ | K::NE | K::LT | K::GT | K::LE | K::GE));
        f.prev = Some((kind, end));
        f.prev_word = if kind == K::IDENT {
            remembered(text)
        } else {
            ""
        };
        self.raw = raw;
    }
}

/// The length in bytes of `word`'s first character (0 for an empty word).
/// `word` after its first character.
fn after_first(word: &str) -> &str {
    let mut chars = word.chars();
    chars.next();
    chars.as_str()
}

fn starts_with_sign(word: &str) -> bool {
    word.starts_with(['+', '-'])
}

fn search_kind(token: Search, text: &str) -> K {
    match token {
        Search::Whitespace => K::WHITESPACE,
        Search::Backtick(Tick::Comment) => K::COMMENT,
        Search::Backtick(Tick::Macro) => K::MACRO_TOKEN,
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

fn expr_kind(token: Expr) -> K {
    match token {
        Expr::Whitespace => K::WHITESPACE,
        Expr::Backtick(Tick::Comment) => K::COMMENT,
        Expr::Backtick(Tick::Macro) => K::MACRO_TOKEN,
        Expr::Ident => K::IDENT,
        Expr::Number => K::NUMBER_TOKEN,
        Expr::Dynamic => K::DYNAMIC_NAME,
        Expr::TokenName => K::TOKEN_NAME,
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
pub fn lex(source: &str) -> Vec<Lexeme> {
    let mut driver = Driver {
        source,
        frames: vec![Frame::new(true)],
        raw: false,
        dead_quotes: [false; 2],
        no_compound_until: 0,
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

    fn kinds(source: &str) -> Vec<(K, &str)> {
        lex(source)
            .iter()
            .filter(|l| l.kind != K::WHITESPACE.raw())
            .map(|l| {
                let kind = <crate::syntax::kind::Lang as rowan::Language>::kind_from_raw(l.kind);
                (
                    kind,
                    source.get(std::ops::Range::<usize>::from(l.range)).unwrap(),
                )
            })
            .collect()
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

    #[test]
    fn a_signed_word_may_start_with_any_character() {
        // The nightly fuzzer (crash-fd275c9b): `slice[1..]` cut inside the
        // first character of a word in `dedup`, `fields` or `sort`.
        for source in [
            "| dedup \u{70f}+a",
            "| sort \u{e9}+x",
            "| fields \u{1f600}+",
            "| dedup \u{70f}",
        ] {
            let lexemes = lex(source);
            assert_eq!(
                lexemes.last().map(|l| usize::from(l.range.end())),
                Some(source.len()),
                "{source:?}"
            );
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

    #[test]
    fn scans_read_multi_byte_text() {
        assert_eq!(callword_len("now()😀"), Some(5));
        assert_eq!(callword_len("é()"), None);
        assert_eq!(term_text_len("é😀 x"), "é😀".len());
        assert_eq!(term_text_len("é\"😀 )\"😀) x"), "é\"😀 )\"😀".len());
        assert_eq!(term_text_len("😀|x"), "😀".len());
        assert_eq!(
            compound_len("a=\"é\"😀\\é x"),
            (Some("a=\"é\"😀\\é".len()), "a=\"é\"😀\\é".len(), true)
        );
        assert_eq!(compound_len("é😀 x"), (None, "é😀".len(), false));
        assert_eq!(after_first("😀é"), "é");
        assert_eq!(after_first(""), "");
        // A word cut at its quote, and at a `+` after its first character.
        let source = "| rename é😀'x' as y | fields + \u{70f}+é";
        let text: String = kinds(source).iter().map(|(_, text)| *text).collect();
        assert_eq!(text, source.replace(' ', ""));
    }
}
