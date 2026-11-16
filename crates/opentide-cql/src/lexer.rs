//! The CQL lexer: logos for the punctuation, hand scanners for the words, and the modes the
//! tree-sitter grammar's context-aware lexing and its C scanner gave it.
//!
//! tree-sitter lexed what the parser could accept next (`valid_symbols`): the same bytes are a
//! pattern in a filter, a field reference in an expression and a division where an operator is
//! due. A pre-lexed token stream has no parser to ask, so [`Driver`] follows the grammar at the
//! level of tokens: a [`Mode`] says what is valid next and a stack of [`Frame`]s says where the
//! brackets return to. Only what changes a token's extent or kind is tracked; everything else is
//! the parser's business. Words are not keywords here: `and`, `or`, `not`, `case`, `match`,
//! `like`, `true` and `false` are [`K::WORD`] and the parser re-kinds them.
//!
//! The scanner (`scanner.c`) is [`scan`]: function names, unquoted patterns, and the field of an
//! assignment, ported rule for rule. The slash that closes a regex is part of [`Driver::regex`].
//! The lexer tiles the source, whitespace and comments included, and never skips.

use crate::syntax::SyntaxKind as K;
use logos::Logos;
use opentide_parse::Lexeme;
use rowan::{TextRange, TextSize};

/// The tokens that are fixed text. logos takes the longest, so `<=>` beats `<=`.
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
enum Punct {
    #[token("|")]
    Pipe,
    #[token("=")]
    Eq,
    #[token("!=")]
    NotEq,
    #[token("==")]
    EqEq,
    #[token("<")]
    Lt,
    #[token("<=")]
    LtEq,
    #[token(">")]
    Gt,
    #[token(">=")]
    GtEq,
    #[token("<=>")]
    LtEqGt,
    #[token(":=")]
    ColonEq,
    #[token("=~")]
    EqTilde,
    #[token("=>")]
    FatArrow,
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
    #[token(",")]
    Comma,
    #[token(";")]
    Semi,
    #[token(":")]
    Colon,
    #[token("$")]
    Dollar,
    #[token("?")]
    Question,
    #[token("?{")]
    QuestionLBrace,
}

impl Punct {
    fn kind(self) -> K {
        match self {
            Self::Pipe => K::PIPE,
            Self::Eq => K::EQ,
            Self::NotEq => K::NOT_EQ,
            Self::EqEq => K::EQ_EQ,
            Self::Lt => K::LT,
            Self::LtEq => K::LT_EQ,
            Self::Gt => K::GT,
            Self::GtEq => K::GT_EQ,
            Self::LtEqGt => K::LT_EQ_GT,
            Self::ColonEq => K::COLON_EQ,
            Self::EqTilde => K::EQ_TILDE,
            Self::FatArrow => K::FAT_ARROW,
            Self::Bang => K::BANG,
            Self::Plus => K::PLUS,
            Self::Minus => K::MINUS,
            Self::Star => K::STAR,
            Self::Slash => K::SLASH,
            Self::Percent => K::PERCENT,
            Self::LParen => K::L_PAREN,
            Self::RParen => K::R_PAREN,
            Self::LBrack => K::L_BRACK,
            Self::RBrack => K::R_BRACK,
            Self::LBrace => K::L_BRACE,
            Self::RBrace => K::R_BRACE,
            Self::Comma => K::COMMA,
            Self::Semi => K::SEMI,
            Self::Colon => K::COLON,
            Self::Dollar => K::DOLLAR,
            Self::Question => K::QUESTION,
            Self::QuestionLBrace => K::QUESTION_L_BRACE,
        }
    }
}

/// What the grammar accepts next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// A step or a filter starts, or one follows another: free text, a call and an assignment
    /// are all valid.
    Step,
    /// After an assignment with no pipe: only a call or another assignment may follow (a filter
    /// there would make `x := a - 1` read `x := a` and the free text `- 1`).
    AfterAssign,
    /// A `match` guard: a pattern, a regex, a parameter or a call.
    Guard,
    /// After `=`, `!=` or `like`, and in saved-query arguments: a value.
    Value,
    /// After `<`, `<=`, `>` or `>=`: a number, a string or a parameter.
    Cmp,
    /// After `<=>` of a link constraint: a field.
    Link,
    /// The name of a parameter in `?{name=default}`.
    PName,
    /// An operand of an expression; `elem` when an assignment may start too (an array element).
    Operand { elem: bool },
    /// An operator, a separator or a closing bracket.
    After,
    /// The name of a saved-query argument.
    ArgName,
}

/// What an open bracket is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Frame {
    /// A group of filters.
    ParenFilter,
    /// A group in an expression.
    ParenExpr,
    /// The arguments of a function call.
    Func,
    /// The arguments of a saved query.
    Saved,
    /// `case { ... }`.
    Case,
    /// `field match { ... }`.
    Match,
    /// `{ pipeline }` in an expression.
    Subquery,
    /// `?{name=default}`.
    Param,
    /// `[ ... ]`.
    Brack,
    /// The value of an assignment, which ends where no operator follows.
    Rhs,
}

/// A bracket and the mode that follows its close.
#[derive(Clone, Copy, Debug)]
struct Open {
    frame: Frame,
    ret: Mode,
}

/// The last token, for the few places that look back.
#[derive(Clone, Copy, Debug)]
struct Prev {
    kind: K,
    end: usize,
    is_match: bool,
    saved_name: bool,
}

/// What the scanner may return where it is called.
#[derive(Clone, Copy, Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the scanner's four valid symbols"
)]
struct Flags {
    free: bool,
    value: bool,
    function: bool,
    assign: bool,
}

// ---- Characters ----------------------------------------------------------------------------

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c')
}

fn is_alpha(c: char) -> bool {
    c.is_ascii_alphabetic()
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Appendix C `FieldChar`: "other Unicode up to U+FFFF", read in UTF-16 code
/// units as LogScale's JVM lexer reads it, so a character above U+FFFF (two
/// surrogates, each below it) is a field character too. It is the scanner's
/// [`is_scan_char`]: a word and the scanner must agree on where a run of
/// field characters ends, or the scanner re-reads the whole run at each
/// character the word refuses (quadratic, #1231).
fn is_field_char(c: char) -> bool {
    is_scan_char(c)
}

/// A field character as `scanner.c` reads it: any Unicode beyond Latin-1.
fn is_scan_char(c: char) -> bool {
    matches!(c, '#' | '%' | '&' | '.' | '@' | '^' | '~' | '\\')
        || is_ident(c)
        || (u32::from(c) >= 0xA1 && !matches!(u32::from(c), 0xAB | 0xAD | 0xBB))
}

/// The characters a pattern adds to the field characters (`:` is handled apart).
fn is_pattern_only(c: char) -> bool {
    matches!(c, '*' | '+' | '-' | '/')
}

fn char_at(s: &str, i: usize) -> Option<char> {
    s.get(i..).and_then(|rest| rest.chars().next())
}

/// `from` advanced over the characters `keep` accepts.
fn skip_while(s: &str, mut from: usize, keep: impl Fn(char) -> bool) -> usize {
    while let Some(c) = char_at(s, from) {
        if !keep(c) {
            break;
        }
        from += c.len_utf8();
    }
    from
}

/// `(\[[0-9]*\][FIELD_CHAR]*)*` after a word or a tag: `a[0].b[]`.
fn index_tail(s: &str, mut i: usize) -> usize {
    while char_at(s, i) == Some('[') {
        let j = skip_while(s, i + 1, |c| c.is_ascii_digit());
        if char_at(s, j) != Some(']') {
            break;
        }
        i = skip_while(s, j + 1, is_field_char);
    }
    i
}

/// The end of a `_word` at `i`: a field character but `#`, field characters, array indexes.
fn word_end(s: &str, i: usize) -> Option<usize> {
    let first = char_at(s, i).filter(|&c| is_field_char(c) && c != '#')?;
    let j = skip_while(s, i + first.len_utf8(), is_field_char);
    Some(index_tail(s, j))
}

/// The end of a `tag` at `i`: `#`, field characters, array indexes.
fn tag_end(s: &str, i: usize) -> Option<usize> {
    (char_at(s, i) == Some('#')).then(|| index_tail(s, skip_while(s, i + 1, is_field_char)))
}

/// The end of a `number` at `i`: `-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?`.
fn number_end(s: &str, i: usize) -> Option<usize> {
    let digits = |from: usize| {
        let end = skip_while(s, from, |c| c.is_ascii_digit());
        (end > from).then_some(end)
    };
    let start = if char_at(s, i) == Some('-') { i + 1 } else { i };
    let mut end = digits(start)?;
    if let Some(frac) = digits(end + 1).filter(|_| char_at(s, end) == Some('.')) {
        end = frac;
    }
    if matches!(char_at(s, end), Some('e' | 'E')) {
        let sign = end + 1 + usize::from(matches!(char_at(s, end + 1), Some('+' | '-')));
        if let Some(exp) = digits(sign) {
            end = exp;
        }
    }
    Some(end)
}

/// The end of an `_expression_pattern` at `i`: `*` or a sign, then field characters and
/// `* + - : /`.
fn expr_pattern_end(s: &str, i: usize) -> Option<usize> {
    let body = |c: char| is_field_char(c) || matches!(c, '*' | '+' | '-' | ':' | '/');
    match char_at(s, i)? {
        '*' => Some(skip_while(s, i + 1, body)),
        '+' | '-' => {
            let end = skip_while(s, i + 1, body);
            (end > i + 1).then_some(end)
        }
        _ => None,
    }
}

/// Where a scan for a closing delimiter already failed: every later start of the same kind
/// fails too (the scan from there walks the same characters), so it is not repeated, which
/// would make a source of unterminated openers quadratic.
#[derive(Clone, Copy, Debug)]
struct Memo {
    /// No `*/` follows a `/*` from here on.
    block: usize,
    /// No closing quote follows a `"` from here on.
    string: usize,
    /// No `]` follows a `[` from here to the end of the line (`.1`).
    class: (usize, usize),
}

impl Memo {
    const NONE: Self = Self {
        block: usize::MAX,
        string: usize::MAX,
        class: (usize::MAX, 0),
    };
}

/// The end of a string at `i`: `"([^"\\]|\\.)*"`; unterminated is no token.
fn string_end(s: &str, i: usize, memo: &mut Memo) -> Option<usize> {
    if char_at(s, i) != Some('"') || i >= memo.string {
        return None;
    }
    let mut j = i + 1;
    let end = loop {
        match char_at(s, j) {
            None => break None,
            Some('"') => break Some(j + 1),
            Some('\\') => match char_at(s, j + 1) {
                Some(c) => j += 1 + c.len_utf8(),
                None => break None,
            },
            Some(c) => j += c.len_utf8(),
        }
    };
    if end.is_none() {
        memo.string = i;
    }
    end
}

/// The end of a line comment at `i`, or of a terminated block comment (they do not nest).
fn comment_end(s: &str, i: usize, memo: &mut Memo) -> Option<(K, usize)> {
    let rest = s.get(i..)?;
    if rest.starts_with("//") {
        let end = skip_while(s, i, |c| c != '\r' && c != '\n');
        Some((K::LINE_COMMENT, end))
    } else if rest.starts_with("/*") && i < memo.block {
        let Some(close) = rest.get(2..).and_then(|body| body.find("*/")) else {
            memo.block = i;
            return None;
        };
        Some((K::BLOCK_COMMENT, i + 2 + close + 2))
    } else {
        None
    }
}

/// The end of the class that starts at the `[` at `i`: `\[\^?\]?([^\]\\\r\n]|\\[^\r\n])*\]`.
fn class_end(s: &str, i: usize, memo: &mut Memo) -> Option<usize> {
    if i >= memo.class.0 && i < memo.class.1 {
        return None;
    }
    let end = class_close(s, i);
    if end.is_none() {
        memo.class = (i, skip_while(s, i, |c| c != '\r' && c != '\n'));
    }
    end
}

fn class_close(s: &str, i: usize) -> Option<usize> {
    let mut start = i + 1;
    if char_at(s, start) == Some('^') {
        start += 1;
    }
    // A `]` right after `[` or `[^` is a member; if no `]` closes the class, it closes it.
    let from_member = (char_at(s, start) == Some(']')).then_some(start + 1);
    let close = |mut j: usize| loop {
        match char_at(s, j)? {
            ']' => return Some(j + 1),
            '\\' => {
                let c = char_at(s, j + 1).filter(|&c| c != '\r' && c != '\n')?;
                j += 1 + c.len_utf8();
            }
            '\r' | '\n' => return None,
            c => j += c.len_utf8(),
        }
    };
    from_member.and_then(close).or_else(|| close(start))
}

/// The end of a regex body at `i`: one or more of a character but `/ \ [` and a line break, an
/// escape, a class. `None` for an empty body.
fn regex_body_end(s: &str, i: usize, memo: &mut Memo) -> Option<usize> {
    let mut j = i;
    loop {
        match char_at(s, j) {
            None | Some('/' | '\r' | '\n') => break,
            Some('\\') => match char_at(s, j + 1) {
                Some(c) if c != '\r' && c != '\n' => j += 1 + c.len_utf8(),
                _ => break,
            },
            Some('[') => match class_end(s, j, memo) {
                Some(end) => j = end,
                None => break,
            },
            Some(c) => j += c.len_utf8(),
        }
    }
    (j > i).then_some(j)
}

// ---- The scanner ---------------------------------------------------------------------------

// The characters [`scan`] has read on this thread: a test bounds the reads per
// character of a source, so a rescan of a run cannot come back unnoticed.
#[cfg(test)]
thread_local! {
    static SCANNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// `scanner.c`: the tokens a regular expression cannot read because they depend on what
/// follows. Returns the token (`WORD` is the field of an assignment) and its end.
#[expect(
    clippy::too_many_lines,
    reason = "a port of one C function, kept in the shape of the original"
)]
fn scan(s: &str, start: usize, flags: Flags) -> Option<(K, usize)> {
    #[derive(PartialEq, Clone, Copy)]
    enum Shape {
        Ident1,
        Colon,
        Ident2,
        Other,
    }
    let want_pattern = flags.free || flags.value;
    let want_function = flags.function || flags.free;
    let want_assign = flags.assign;
    if !want_function && !want_pattern && !want_assign {
        return None;
    }
    let first = char_at(s, start)?;
    if want_pattern {
        if first == '/' || !(is_scan_char(first) || is_pattern_only(first) || first == ':') {
            return None;
        }
    } else if !(is_alpha(first) || want_assign && first != '#' && is_scan_char(first)) {
        return None;
    }
    let mut shape = if is_alpha(first) {
        Shape::Ident1
    } else {
        Shape::Other
    };
    let mut has_pattern_char = false;
    let mut before_assign = false;
    let mut length = 0usize;
    let mut word = [0u8; 3];
    let (mut last, mut before_last) = ('\0', '\0');
    let (mut i, mut end) = (start, start);
    while let Some(c) = char_at(s, i) {
        #[cfg(test)]
        SCANNED.with(|n| n.set(n.get() + 1));
        if c == ':' {
            i += 1;
            if char_at(s, i) == Some('=') {
                before_assign = true;
                break;
            }
            shape = if shape == Shape::Ident1 {
                Shape::Colon
            } else {
                Shape::Other
            };
            has_pattern_char = true;
            // Without a pattern to read, only an assignment's field (no
            // pattern character) or a call's name (`a` or `a:b`) is a token:
            // past a second colon neither can be, so reading on to the end of
            // the run would find nothing, and the word stops at this colon:
            // the run's next segment would re-read the rest (quadratic).
            if !want_pattern && shape == Shape::Other {
                break;
            }
        } else if is_scan_char(c) || (want_pattern && is_pattern_only(c)) {
            if !is_ident(c) {
                shape = Shape::Other;
                if !want_pattern && !want_assign {
                    break;
                }
            } else if shape == Shape::Colon {
                shape = if is_alpha(c) {
                    Shape::Ident2
                } else {
                    Shape::Other
                };
            }
            if is_pattern_only(c) {
                has_pattern_char = true;
            }
            if let Some(slot) = word.get_mut(length) {
                *slot = u8::try_from(c.to_ascii_lowercase()).unwrap_or(0);
            }
            i += c.len_utf8();
        } else {
            break;
        }
        length += 1;
        before_last = last;
        last = c;
        end = i;
    }
    if length == 0 {
        return None;
    }
    // What directly follows the word, before any look past blanks below.
    let after_word = char_at(s, i);
    if want_assign && !has_pattern_char {
        // `name :=`: blanks may stand between the name and `:=`.
        if !before_assign {
            let j = skip_while(s, i, is_space);
            if char_at(s, j) == Some(':') {
                before_assign = char_at(s, j + 1) == Some('=');
            }
        }
        if before_assign {
            return Some((K::ASSIGN_FIELD_TOKEN, end));
        }
    }
    if want_function
        && !before_assign
        && matches!(shape, Shape::Ident1 | Shape::Ident2)
        && after_word == Some('(')
    {
        let keyword = (length == 3 && (&word == b"and" || &word == b"not"))
            || (length == 2 && &word[..2] == b"or");
        if !keyword {
            return Some((K::FUNCTION_NAME_TOKEN, end));
        }
    }
    if !want_pattern {
        return None;
    }
    if last == '/' && before_last == '/' {
        return Some((K::PATTERN_ERROR, end));
    }
    has_pattern_char.then_some((K::PATTERN, end))
}

// ---- The driver ----------------------------------------------------------------------------

/// Lexes `source`: every byte is in exactly one lexeme.
pub(crate) fn lex(source: &str) -> Vec<Lexeme> {
    let mut driver = Driver {
        src: source,
        pos: 0,
        out: Vec::new(),
        stack: Vec::new(),
        mode: Mode::Step,
        prev: Prev {
            kind: K::EOF,
            end: 0,
            is_match: false,
            saved_name: false,
        },
        was_field: false,
        calls_ok: true,
        field_calls: false,
        call_ret: Mode::Step,
        memo: Memo::NONE,
    };
    driver.run();
    driver.out
}

struct Driver<'s> {
    src: &'s str,
    pos: usize,
    out: Vec<Lexeme>,
    stack: Vec<Open>,
    mode: Mode,
    prev: Prev,
    /// The last token was a word, tag or string read as a step's possible field.
    was_field: bool,
    /// A call step (`=~`, `<=>`) may start here: after a pipe, a call or an assignment, not
    /// after a filter. tree-sitter reads `a b =~ f()` as `a`, `b = ~`, then a call.
    calls_ok: bool,
    /// `calls_ok` when the possible field was read.
    field_calls: bool,
    /// The mode after the call whose name was just read.
    call_ret: Mode,
    memo: Memo,
}

fn range(start: usize, end: usize) -> TextRange {
    let offset = |n: usize| TextSize::from(u32::try_from(n).unwrap_or(u32::MAX));
    TextRange::new(offset(start), offset(end.max(start)))
}

impl Driver<'_> {
    fn run(&mut self) {
        while self.pos < self.src.len() {
            if self.trivia() {
                continue;
            }
            if self.mode == Mode::After {
                self.settle();
            }
            self.token();
        }
    }

    /// Whitespace and comments, valid everywhere.
    fn trivia(&mut self) -> bool {
        let start = self.pos;
        let (kind, end) = if char_at(self.src, start).is_some_and(is_space) {
            (K::WHITESPACE, skip_while(self.src, start, is_space))
        } else if let Some(comment) = comment_end(self.src, start, &mut self.memo) {
            comment
        } else {
            return false;
        };
        self.out.push(Lexeme {
            kind: kind.raw(),
            range: range(start, end),
        });
        self.pos = end;
        true
    }

    /// Emits a token from `self.pos` to `end`.
    fn push(&mut self, kind: K, end: usize) {
        let text = self.src.get(self.pos..end).unwrap_or("");
        self.prev = Prev {
            kind,
            end,
            is_match: kind == K::WORD && text == "match",
            saved_name: false,
        };
        self.out.push(Lexeme {
            kind: kind.raw(),
            range: range(self.pos, end),
        });
        self.pos = end;
        self.was_field = false;
    }

    fn top(&self) -> Option<Frame> {
        self.stack.last().map(|open| open.frame)
    }

    fn flags(&self) -> Flags {
        match self.mode {
            Mode::Step => Flags {
                free: true,
                function: true,
                assign: true,
                ..Flags::default()
            },
            Mode::Guard => Flags {
                free: true,
                function: true,
                ..Flags::default()
            },
            Mode::AfterAssign => Flags {
                function: true,
                assign: true,
                ..Flags::default()
            },
            Mode::Value | Mode::PName => Flags {
                value: true,
                ..Flags::default()
            },
            Mode::Operand { elem } => Flags {
                function: true,
                assign: elem,
                ..Flags::default()
            },
            Mode::Cmp | Mode::Link | Mode::After | Mode::ArgName => Flags::default(),
        }
    }

    /// The mode after a value in the current mode.
    fn after_atom(&mut self) {
        self.mode = self.after_atom_mode();
    }

    fn after_atom_mode(&self) -> Mode {
        match self.mode {
            Mode::Step | Mode::Guard | Mode::Cmp | Mode::Link => Mode::Step,
            Mode::AfterAssign => Mode::AfterAssign,
            Mode::Value => match self.top() {
                Some(Frame::Saved | Frame::Param) => Mode::After,
                _ => Mode::Step,
            },
            Mode::PName | Mode::Operand { .. } | Mode::ArgName | Mode::After => Mode::After,
        }
    }

    /// Whether the next token continues an expression: a binary operator.
    fn continues(&self) -> bool {
        let rest = self.src.get(self.pos..).unwrap_or("");
        rest.starts_with("==")
            || rest.starts_with("!=")
            || rest.starts_with(['<', '>', '+', '-', '*', '/', '%'])
    }

    /// An assignment's value ends where no operator follows it.
    fn settle(&mut self) {
        while self.mode == Mode::After && self.top() == Some(Frame::Rhs) && !self.continues() {
            if let Some(open) = self.stack.pop() {
                self.mode = open.ret;
                // An assignment is a step: a call step may follow.
                self.calls_ok = true;
            }
        }
    }

    fn token(&mut self) {
        let start = self.pos;
        let was_field = self.was_field;
        if let Some((kind, end)) = scan(self.src, start, self.flags()) {
            match kind {
                K::FUNCTION_NAME_TOKEN => {
                    self.call_ret =
                        if matches!(self.mode, Mode::Step | Mode::Guard | Mode::AfterAssign) {
                            Mode::Step
                        } else {
                            Mode::After
                        };
                    self.push(kind, end);
                }
                // The field of an assignment: `:=` follows.
                K::ASSIGN_FIELD_TOKEN => {
                    self.push(kind, end);
                    if matches!(self.mode, Mode::Operand { .. }) {
                        self.mode = Mode::After;
                    }
                }
                K::PATTERN => {
                    self.push(kind, end);
                    self.after_atom();
                    self.calls_ok = false;
                }
                _ => self.push(kind, end),
            }
            return;
        }
        let Some(c) = char_at(self.src, start) else {
            return;
        };
        if self.atom(c, was_field) {
            return;
        }
        let mut punct = Punct::lexer(self.src.get(start..).unwrap_or(""));
        match punct.next() {
            Some(Ok(p)) => {
                let mut kind = p.kind();
                let mut end = start + punct.span().end;
                // tree-sitter lexes what the grammar accepts there: `=~`, `<=>` and `=>` are
                // shorter where they are not valid (`a b =~ f()` is `a`, `b = ~`, a call).
                let stepwise = matches!(self.mode, Mode::Step | Mode::AfterAssign);
                let call_ok = was_field && self.field_calls;
                match kind {
                    K::EQ_TILDE if !(stepwise && call_ok) => (kind, end) = (K::EQ, start + 1),
                    K::LT_EQ_GT if !(self.mode == Mode::After || (stepwise && call_ok)) => {
                        (kind, end) = (K::LT_EQ, start + 2);
                    }
                    K::FAT_ARROW if !stepwise => (kind, end) = (K::EQ, start + 1),
                    K::EQ_EQ if self.mode != Mode::After => (kind, end) = (K::EQ, start + 1),
                    _ => {}
                }
                self.punct(kind, end);
            }
            _ => self.push(K::ERROR_TOKEN, start + c.len_utf8()),
        }
    }

    /// A string, tag, number, word, regex or pattern; whether `c` started one.
    fn atom(&mut self, c: char, was_field: bool) -> bool {
        let (s, start) = (self.src, self.pos);
        // Where an operator is due, `%` is the operator, not a field character (a word there
        // is an attribute name: `{ ... } include: [a]`).
        if self.mode == Mode::After && c == '%' {
            return false;
        }
        let step_like = matches!(self.mode, Mode::Step | Mode::Guard | Mode::Value);
        let (kind, end) = if let Some(end) = string_end(s, start, &mut self.memo) {
            (K::STRING_TOKEN, end)
        } else if c == '/' && step_like {
            return self.regex();
        } else if matches!(self.mode, Mode::Cmp) {
            match number_end(s, start) {
                Some(end) => (K::NUMBER_TOKEN, end),
                None => return false,
            }
        } else if matches!(self.mode, Mode::Operand { .. }) {
            // The longest of number, tag, pattern, word; a tie goes to the first listed.
            let found = [
                (K::NUMBER_TOKEN, number_end(s, start)),
                (K::TAG_TOKEN, tag_end(s, start)),
                (K::PATTERN, expr_pattern_end(s, start)),
                (K::WORD, word_end(s, start)),
            ]
            .into_iter()
            .filter_map(|(kind, end)| end.map(|end| (kind, end)))
            .fold(None::<(K, usize)>, |best, found| match best {
                Some(best) if best.1 >= found.1 => Some(best),
                _ => Some(found),
            });
            match found {
                Some(found) => found,
                None => return false,
            }
        } else if let Some(end) = tag_end(s, start) {
            (K::TAG_TOKEN, end)
        } else if let Some(end) = word_end(s, start) {
            (K::WORD, end)
        } else {
            return false;
        };
        let text = s.get(start..end).unwrap_or("");
        let stepwise = matches!(self.mode, Mode::Step | Mode::AfterAssign);
        let calls_ok = self.calls_ok;
        let link = self.mode == Mode::Link;
        self.push(kind, end);
        self.calls_ok = link;
        if kind == K::WORD && stepwise {
            self.word_in_step(text, was_field);
            self.field_calls = calls_ok;
        } else {
            let field = matches!(kind, K::TAG_TOKEN | K::STRING_TOKEN) && stepwise;
            self.after_atom();
            self.was_field = field;
            self.field_calls = calls_ok;
        }
        true
    }

    /// A word in a step: a possible field, and `like` after one.
    fn word_in_step(&mut self, text: &str, was_field: bool) {
        if was_field && text == "like" {
            self.mode = Mode::Value;
        } else {
            self.was_field = !["and", "or", "not"]
                .iter()
                .any(|kw| text.eq_ignore_ascii_case(kw));
        }
    }

    /// `/regex/flags` where a regex may start; the slash that closes it comes from the scanner
    /// in the grammar, here it is the next character.
    fn regex(&mut self) -> bool {
        let s = self.src;
        let open = self.pos;
        self.push(K::SLASH, open + 1);
        if let Some(body) = regex_body_end(s, open + 1, &mut self.memo) {
            self.push(K::REGEX_PATTERN_TOKEN, body);
            if char_at(s, body) == Some('/') {
                self.push(K::SLASH, body + 1);
                self.after_atom();
                // The flags are immediate and compete with what may follow: the scanner and
                // a longer word win (`/x/ia:b`, `/x/i7`).
                let from = body + 1;
                let flags = skip_while(s, from, |c| c.is_ascii_alphabetic());
                let beaten = scan(s, from, self.flags()).is_some()
                    || word_end(s, from).is_some_and(|word| word > flags);
                if flags > from && !beaten {
                    self.push(K::REGEX_FLAGS_TOKEN, flags);
                }
                self.calls_ok = false;
                return true;
            }
        }
        self.after_atom();
        self.calls_ok = false;
        true
    }

    /// A fixed token, and what it does to the mode and the brackets.
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per token: the transition table"
    )]
    fn punct(&mut self, kind: K, end: usize) {
        let start = self.pos;
        let prev = self.prev;
        let mode = if self.mode == Mode::AfterAssign {
            Mode::Step
        } else {
            self.mode
        };
        let value_ret = self.after_atom_mode();
        self.push(kind, end);
        match kind {
            K::L_PAREN => {
                if prev.saved_name && prev.end == start {
                    self.open(Frame::Saved, Mode::Step, Mode::ArgName);
                } else if prev.kind == K::FUNCTION_NAME_TOKEN && prev.end == start {
                    self.open(Frame::Func, self.call_ret, Mode::Operand { elem: false });
                } else if matches!(mode, Mode::Operand { .. }) {
                    self.open(Frame::ParenExpr, Mode::After, Mode::Operand { elem: false });
                } else {
                    self.open(Frame::ParenFilter, Mode::Step, Mode::Step);
                }
            }
            K::L_BRACK => {
                let ret = match mode {
                    Mode::Step | Mode::Guard => Mode::Step,
                    Mode::Value => value_ret,
                    _ => Mode::After,
                };
                self.open(Frame::Brack, ret, Mode::Operand { elem: true });
            }
            K::L_BRACE => match mode {
                Mode::Operand { .. } | Mode::After => {
                    self.open(Frame::Subquery, Mode::After, Mode::Step);
                }
                _ if prev.is_match => self.open(Frame::Match, Mode::Step, Mode::Guard),
                _ => self.open(Frame::Case, Mode::Step, Mode::Step),
            },
            K::QUESTION_L_BRACE => self.open(Frame::Param, value_ret, Mode::PName),
            K::QUESTION => self.parameter(),
            K::DOLLAR if mode == Mode::Step => self.saved_query(),
            K::R_PAREN | K::R_BRACK | K::R_BRACE => self.close(kind),
            K::PIPE => {
                self.pop_rhs();
                self.mode = Mode::Step;
                self.calls_ok = true;
            }
            K::BANG => self.calls_ok = false,
            K::SEMI => {
                self.pop_rhs();
                self.calls_ok = true;
                self.mode = if self.top() == Some(Frame::Match) {
                    Mode::Guard
                } else {
                    Mode::Step
                };
            }
            K::COMMA => {
                self.pop_rhs();
                self.mode = match self.top() {
                    Some(Frame::Func) => Mode::Operand { elem: false },
                    Some(Frame::Brack) => Mode::Operand { elem: true },
                    Some(Frame::Saved) => Mode::ArgName,
                    _ => Mode::Step,
                };
            }
            K::EQ | K::NOT_EQ => {
                self.mode = match (mode, self.top()) {
                    (Mode::Step, _) => Mode::Value,
                    (Mode::After, Some(Frame::Saved | Frame::Param)) if kind == K::EQ => {
                        Mode::Value
                    }
                    (Mode::After, _) => Mode::Operand { elem: false },
                    _ => mode,
                };
            }
            K::COLON_EQ => match mode {
                Mode::Step => {
                    self.open(Frame::Rhs, Mode::AfterAssign, Mode::Operand { elem: false });
                }
                Mode::After => self.open(Frame::Rhs, Mode::After, Mode::Operand { elem: false }),
                _ => {}
            },
            K::LT | K::LT_EQ | K::GT | K::GT_EQ => {
                self.mode = match mode {
                    Mode::Step => Mode::Cmp,
                    Mode::After => Mode::Operand { elem: false },
                    _ => mode,
                };
            }
            K::LT_EQ_GT if mode == Mode::Step => self.mode = Mode::Link,
            K::EQ_EQ
            | K::LT_EQ_GT
            | K::PLUS
            | K::MINUS
            | K::STAR
            | K::SLASH
            | K::PERCENT
            | K::COLON => {
                if mode == Mode::After {
                    self.mode = Mode::Operand { elem: false };
                }
            }
            K::EQ_TILDE => self.mode = Mode::Step,
            K::FAT_ARROW => {
                self.mode = Mode::Step;
                self.calls_ok = true;
            }
            _ => {}
        }
    }

    fn open(&mut self, frame: Frame, ret: Mode, mode: Mode) {
        self.stack.push(Open { frame, ret });
        self.mode = mode;
        // A group of filters holds filters; a body holds steps.
        self.calls_ok = !matches!(frame, Frame::ParenFilter);
    }

    fn pop_rhs(&mut self) {
        while self.top() == Some(Frame::Rhs) {
            self.stack.pop();
        }
    }

    fn close(&mut self, kind: K) {
        self.pop_rhs();
        let matches = |frame: Frame| match kind {
            K::R_PAREN => matches!(
                frame,
                Frame::ParenFilter | Frame::ParenExpr | Frame::Func | Frame::Saved
            ),
            K::R_BRACK => frame == Frame::Brack,
            _ => matches!(
                frame,
                Frame::Case | Frame::Match | Frame::Subquery | Frame::Param
            ),
        };
        if self.top().is_some_and(matches) {
            if let Some(open) = self.stack.pop() {
                self.mode = open.ret;
                // A call, a saved query, a stats shorthand or a body is a step; a group is a
                // filter.
                self.calls_ok = !matches!(open.frame, Frame::ParenFilter | Frame::Param);
            }
        } else if self.stack.is_empty() {
            self.mode = Mode::Step;
        }
    }

    /// `?name` or `?"quoted name"`, after the `?` (`[FIELD_CHAR\-]+`).
    fn parameter(&mut self) {
        let (s, start) = (self.src, self.pos);
        let end = string_end(s, start, &mut self.memo)
            .map(|end| (K::STRING_TOKEN, end))
            .or_else(|| {
                let end = skip_while(s, start, |c| is_field_char(c) || c == '-');
                (end > start).then_some((K::PARAMETER_NAME_TOKEN, end))
            });
        if let Some((kind, end)) = end {
            self.push(kind, end);
        }
        self.after_atom();
        self.calls_ok = false;
    }

    /// `$name` or `$"quoted name"`, after the `$` (`[FIELD_CHAR*+\-:/]+`); `(` follows.
    fn saved_query(&mut self) {
        let (s, start) = (self.src, self.pos);
        let (kind, end) = match string_end(s, start, &mut self.memo) {
            Some(end) => (K::STRING_TOKEN, end),
            None => (
                K::SAVED_QUERY_NAME_TOKEN,
                skip_while(s, start, |c| {
                    is_field_char(c) || is_pattern_only(c) || c == ':'
                }),
            ),
        };
        // A comment that starts here and is longer than the name wins (`$/*x ... */`): the
        // longest token does, in tree-sitter.
        let comment = comment_end(s, start, &mut self.memo).is_some_and(|(_, c)| c > end);
        if end > start && !comment {
            self.push(kind, end);
            self.prev.saved_name = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<(K, &str)> {
        lex(source)
            .iter()
            .map(|l| {
                let r = std::ops::Range::<usize>::from(l.range);
                (K::from_raw(l.kind), &source[r])
            })
            .filter(|(k, _)| *k != K::WHITESPACE)
            .collect()
    }

    /// The scanner reads each character of a source a bounded number of
    /// times. A word that stopped at U+FFFF while the scanner read on made it
    /// re-read a whole run of characters above U+FFFF at each of them
    /// (`"\u{1F600}"` x 10,000 took seconds). Counted, not timed.
    #[test]
    fn the_scanner_reads_each_character_a_bounded_number_of_times() {
        let n = 5_000;
        for unit in [
            "\u{1F600}",
            "\u{e9}\u{1F600}",
            "a\u{1F600}",
            "\u{1F600} ",
            "x=\u{1F600} | ",
            "a ",
            "a=b | ",
            "#t=a* ",
            "f(x) ",
        ] {
            let source = unit.repeat(n);
            assert_bounded_reads(&source);
        }
        // After `:=` the scanner reads for an assignment or a call, not a
        // pattern: a run of colon segments was re-read at each colon.
        for unit in ["a:", "\u{1F600}:", "\u{e9}:", "a:b:"] {
            assert_bounded_reads(&format!("x := {}", unit.repeat(n)));
            assert_bounded_reads(&format!("x := f({})", unit.repeat(n)));
        }
    }

    /// Lexing `source` reads at most three characters per character.
    fn assert_bounded_reads(source: &str) {
        SCANNED.with(|count| count.set(0));
        let lexemes = lex(source);
        let read = SCANNED.with(std::cell::Cell::get);
        let chars = source.chars().count();
        let head: String = source.chars().take(12).collect();
        assert!(
            read <= 3 * chars,
            "`{head}…`: the scanner read {read} characters of {chars}"
        );
        assert!(!lexemes.is_empty());
    }

    /// A character above U+FFFF is a field character, as the scanner and
    /// LogScale's UTF-16 lexer read it: a word runs through it.
    #[test]
    fn a_character_above_u_ffff_is_part_of_a_word() {
        assert_eq!(kinds("a\u{1F600}b"), [(K::WORD, "a\u{1F600}b")]);
        assert_eq!(kinds("\u{e9}\u{1F600}"), [(K::WORD, "\u{e9}\u{1F600}")]);
        let tag = kinds("#tag=\u{1F600}");
        assert_eq!(tag.last(), Some(&(K::WORD, "\u{1F600}")), "{tag:?}");
    }

    #[test]
    fn a_filter_and_a_call() {
        let tokens = kinds("a=b | count(x)");
        let texts: Vec<_> = tokens.iter().map(|(_, t)| *t).collect();
        assert_eq!(texts, ["a", "=", "b", "|", "count", "(", "x", ")"]);
        assert_eq!(tokens[4].0, K::FUNCTION_NAME_TOKEN);
    }
}
