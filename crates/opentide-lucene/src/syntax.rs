//! The Lucene classic query syntax's kinds, lexer and rowan language.
//!
//! The lexer is hand-driven (the toolkit's `Lexeme`s, not a logos token):
//! a range's bounds are lexed by their own rules (`RANGE_GOOP` runs to a
//! space, `]` or `}`; `TO` is a keyword only between them), which no
//! context-free token set can say.

use opentide_parse::{Lexeme, TokenSet};
use rowan::{TextRange, TextSize};

/// A token or node of the Lucene tree. The names follow the tree-sitter
/// grammar this replaces (`grammars/tree-sitter-opentide-lucene`), so the
/// analysis reads the same shapes. Token kinds come first, so every one fits
/// a [`TokenSet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub(crate) enum SyntaxKind {
    // Tokens.
    Whitespace,
    /// A term (`foo`, `a\:b`).
    Term,
    /// A term with an unescaped `*` or `?`.
    WildcardTerm,
    /// A lone `*`.
    Star,
    /// `"a phrase"`.
    Phrase,
    /// `/a regexp/`.
    Regexp,
    /// A bound of a range: a run up to a space, `]` or `}`.
    RangeTerm,
    /// `^2`, `^1.5`.
    Boost,
    /// `~`, `~2`, `~AUTO`.
    Fuzzy,
    /// `+`, `-` or `!` followed by one whitespace character: a term.
    BareOperator,
    /// `AND`.
    AndKw,
    /// `OR`.
    OrKw,
    /// `NOT`.
    NotKw,
    /// `&&`: an operator after a clause, a term anywhere else.
    AmpAmp,
    /// `||`: an operator after a clause, a term anywhere else.
    PipePipe,
    Bang,
    Plus,
    Minus,
    Colon,
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    /// `TO`, between a range's bounds.
    ToKw,
    /// A character no token takes (a lone `\`, `^`, an unclosed `"` or `/`).
    ErrorToken,
    Eof,
    // Nodes.
    SourceFile,
    BooleanQuery,
    And,
    Or,
    Not,
    ModifiedClause,
    Required,
    Prohibited,
    FieldQuery,
    FieldName,
    Group,
    TermQuery,
    PhraseQuery,
    RangeQuery,
    RegexpQuery,
    Error,
}

use SyntaxKind as K;

/// Every kind, in discriminant order: `from_raw` indexes it.
const ALL: [SyntaxKind; 44] = [
    K::Whitespace,
    K::Term,
    K::WildcardTerm,
    K::Star,
    K::Phrase,
    K::Regexp,
    K::RangeTerm,
    K::Boost,
    K::Fuzzy,
    K::BareOperator,
    K::AndKw,
    K::OrKw,
    K::NotKw,
    K::AmpAmp,
    K::PipePipe,
    K::Bang,
    K::Plus,
    K::Minus,
    K::Colon,
    K::LParen,
    K::RParen,
    K::LBracket,
    K::RBracket,
    K::LBrace,
    K::RBrace,
    K::ToKw,
    K::ErrorToken,
    K::Eof,
    K::SourceFile,
    K::BooleanQuery,
    K::And,
    K::Or,
    K::Not,
    K::ModifiedClause,
    K::Required,
    K::Prohibited,
    K::FieldQuery,
    K::FieldName,
    K::Group,
    K::TermQuery,
    K::PhraseQuery,
    K::RangeQuery,
    K::RegexpQuery,
    K::Error,
];

impl SyntaxKind {
    /// The raw rowan kind.
    pub(crate) const fn raw(self) -> rowan::SyntaxKind {
        rowan::SyntaxKind(self as u16)
    }

    /// A set of token kinds.
    pub(crate) const fn set(kinds: &[SyntaxKind]) -> TokenSet {
        let mut set = TokenSet::EMPTY;
        let mut i = 0;
        while i < kinds.len() {
            set = set.with(kinds[i].raw());
            i += 1;
        }
        set
    }

    /// The kind of a raw rowan kind (`Error` for one that is none of ours).
    pub(crate) fn from_raw(raw: rowan::SyntaxKind) -> Self {
        ALL.get(usize::from(raw.0)).copied().unwrap_or(K::Error)
    }
}

/// The rowan language of Lucene.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Lucene {}

impl rowan::Language for Lucene {
    type Kind = SyntaxKind;
    fn kind_from_raw(raw: rowan::SyntaxKind) -> SyntaxKind {
        SyntaxKind::from_raw(raw)
    }
    fn kind_to_raw(kind: SyntaxKind) -> rowan::SyntaxKind {
        kind.raw()
    }
}

/// A node of the tree.
pub(crate) type SyntaxNode = rowan::SyntaxNode<Lucene>;

/// Lucene's whitespace: NBSP is a term character, U+3000 is whitespace.
fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n' | '\u{3000}')
}

/// A character that cannot continue a term (`TERM_CHAR` is everything else,
/// and `*`, `?` besides, which a wildcard takes).
fn ends_term(c: char) -> bool {
    is_ws(c)
        || matches!(
            c,
            '!' | '(' | ')' | ':' | '^' | '[' | ']' | '"' | '{' | '}' | '~' | '/' | '\\'
        )
}

/// What the lexer is reading.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    /// After `[` or `{`: the lower bound.
    Lower,
    /// After the lower bound: `TO`.
    To,
    /// After `TO`: the upper bound.
    Upper,
}

struct Lexer<'s> {
    source: &'s str,
    pos: usize,
    out: Vec<Lexeme>,
    mode: Mode,
}

fn size(n: usize) -> TextSize {
    TextSize::from(u32::try_from(n).unwrap_or(u32::MAX))
}

impl<'s> Lexer<'s> {
    fn rest(&self) -> &'s str {
        &self.source[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn push(&mut self, kind: K, end: usize) {
        self.out.push(Lexeme {
            kind: kind.raw(),
            range: TextRange::new(size(self.pos), size(end)),
        });
        self.pos = end;
    }

    /// The end of the whitespace run at the position.
    fn ws_end(&self) -> usize {
        let rest = self.rest();
        self.pos + rest.len() - rest.trim_start_matches(is_ws).len()
    }

    /// The end of a term-like run starting here, and whether it holds an
    /// unescaped `*` or `?`. `None` when no character starts one.
    fn run(&self) -> Option<(usize, bool)> {
        let mut wild = false;
        let mut end = self.pos;
        let mut chars = self.rest().char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            let at = self.pos + i;
            if c == '\\' {
                match chars.next() {
                    Some((_, e)) => end = at + 1 + e.len_utf8(),
                    None => break,
                }
            } else if c == '*' || c == '?' {
                wild = true;
                end = at + 1;
            } else if ends_term(c) || (i == 0 && matches!(c, '+' | '-')) {
                break;
            } else {
                end = at + c.len_utf8();
            }
        }
        (end > self.pos).then_some((end, wild))
    }

    fn term(&mut self) {
        let Some((end, wild)) = self.run() else {
            // A lone `\` at the end.
            let end = self.pos + self.peek().map_or(1, char::len_utf8);
            self.push(K::ErrorToken, end);
            return;
        };
        let text = &self.source[self.pos..end];
        let kind = match text {
            "*" => K::Star,
            _ if wild => K::WildcardTerm,
            "AND" => K::AndKw,
            "OR" => K::OrKw,
            "NOT" => K::NotKw,
            "&&" => K::AmpAmp,
            "||" => K::PipePipe,
            _ => K::Term,
        };
        self.push(kind, end);
    }

    /// `"..."` with `\x` escapes.
    fn phrase(&mut self) -> Option<usize> {
        let mut chars = self.rest().char_indices().skip(1);
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => {
                    chars.next()?;
                }
                '"' => return Some(self.pos + i + 1),
                _ => {}
            }
        }
        None
    }

    /// `/.../`, where `\/` does not close it; the longest match.
    fn regexp(&mut self) -> Option<usize> {
        let mut candidate = None;
        let mut chars = self.rest().char_indices().skip(1).peekable();
        while let Some((i, c)) = chars.next() {
            match c {
                '/' => return Some(self.pos + i + 1),
                '\\' if matches!(chars.peek(), Some((_, '/'))) => {
                    // `\` alone, then `/` closing, or the pair `\/` and more.
                    candidate = Some(self.pos + i + 2);
                    chars.next();
                }
                _ => {}
            }
        }
        candidate
    }

    /// `^` and its number.
    fn boost(&mut self) -> Option<usize> {
        let bytes = self.rest().as_bytes();
        let digits = |from: usize| {
            bytes[from..]
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .count()
        };
        let int = digits(1);
        if int == 0 {
            return None;
        }
        let mut end = 1 + int;
        if bytes.get(end) == Some(&b'.') {
            let frac = digits(end + 1);
            if frac > 0 {
                end += 1 + frac;
            }
        }
        Some(self.pos + end)
    }

    /// `~` and the term characters after it.
    fn fuzzy(&mut self) -> usize {
        let base = self.pos + 1;
        let mut end = base;
        let mut chars = self.source[base..].char_indices();
        while let Some((i, c)) = chars.next() {
            let at = base + i;
            if c == '\\' {
                match chars.next() {
                    Some((_, e)) => end = at + 1 + e.len_utf8(),
                    None => break,
                }
            } else if ends_term(c) || c == '*' || c == '?' {
                break;
            } else {
                end = at + c.len_utf8();
            }
        }
        end
    }

    /// One bound of a range: a phrase, or a run to a space, `]` or `}`.
    fn bound(&mut self) {
        let c = self.peek().unwrap_or(' ');
        if matches!(c, ']' | '}') || self.peek().is_none() {
            self.mode = Mode::Normal;
            return;
        }
        if c == '"' {
            if let Some(end) = self.phrase() {
                self.push(K::Phrase, end);
                self.mode = if self.mode == Mode::Lower {
                    Mode::To
                } else {
                    Mode::Normal
                };
            } else {
                self.push(K::ErrorToken, self.pos + 1);
                self.mode = Mode::Normal;
            }
            return;
        }
        let len = self
            .rest()
            .find([' ', ']', '}'])
            .unwrap_or(self.rest().len());
        self.push(K::RangeTerm, self.pos + len.max(c.len_utf8()));
        self.mode = if self.mode == Mode::Lower {
            Mode::To
        } else {
            Mode::Normal
        };
    }

    fn next(&mut self) {
        let Some(c) = self.peek() else { return };
        // Where a bound begins only a space is skipped: a tab or a newline
        // there starts the bound (`RANGE_GOOP` takes anything but a space,
        // `]` and `}`).
        if matches!(self.mode, Mode::Lower | Mode::Upper) && c == ' ' {
            let rest = self.rest();
            return self.push(
                K::Whitespace,
                self.pos + rest.len() - rest.trim_start_matches(' ').len(),
            );
        }
        if is_ws(c) && !matches!(self.mode, Mode::Lower | Mode::Upper) {
            self.push(K::Whitespace, self.ws_end());
            return;
        }
        match self.mode {
            Mode::Lower | Mode::Upper => return self.bound(),
            Mode::To => {
                self.mode = Mode::Normal;
                if let Some((end, false)) = self.run()
                    && &self.source[self.pos..end] == "TO"
                {
                    self.mode = Mode::Upper;
                    return self.push(K::ToKw, end);
                }
            }
            Mode::Normal => {}
        }
        self.normal(c);
    }

    fn normal(&mut self, c: char) {
        let one = self.pos + c.len_utf8();
        match c {
            '+' | '-' | '!' => {
                let next = self.source[one..].chars().next();
                if let Some(w) = next.filter(|w| is_ws(*w)) {
                    return self.push(K::BareOperator, one + w.len_utf8());
                }
                let kind = match c {
                    '+' => K::Plus,
                    '-' => K::Minus,
                    _ => K::Bang,
                };
                self.push(kind, one);
            }
            ':' => self.push(K::Colon, one),
            '(' => self.push(K::LParen, one),
            ')' => self.push(K::RParen, one),
            ']' => self.push(K::RBracket, one),
            '}' => self.push(K::RBrace, one),
            '[' | '{' => {
                self.push(if c == '[' { K::LBracket } else { K::LBrace }, one);
                self.mode = Mode::Lower;
            }
            '"' => match self.phrase() {
                Some(end) => self.push(K::Phrase, end),
                None => self.push(K::ErrorToken, one),
            },
            '/' => match self.regexp() {
                Some(end) => self.push(K::Regexp, end),
                None => self.push(K::ErrorToken, one),
            },
            '^' => match self.boost() {
                Some(end) => self.push(K::Boost, end),
                None => self.push(K::ErrorToken, one),
            },
            '~' => {
                let end = self.fuzzy();
                self.push(K::Fuzzy, end);
            }
            _ => self.term(),
        }
    }
}

/// Lexes `source`; the lexemes tile it.
pub(crate) fn lex(source: &str) -> Vec<Lexeme> {
    let mut lexer = Lexer {
        source,
        pos: 0,
        out: Vec::new(),
        mode: Mode::Normal,
    };
    while lexer.pos < source.len() {
        let before = lexer.pos;
        lexer.next();
        if lexer.pos == before {
            // A bound that is not one (`[]`): the closer lexes in normal mode.
            lexer.next();
        }
        debug_assert!(lexer.pos > before, "the lexer stalled at {before}");
    }
    lexer.out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<(SyntaxKind, &str)> {
        lex(source)
            .iter()
            .map(|l| (SyntaxKind::from_raw(l.kind), &source[l.range]))
            .filter(|(k, _)| *k != K::Whitespace)
            .collect()
    }

    #[test]
    fn terms_wildcards_and_operators() {
        assert_eq!(
            kinds(r"a\:b foo* * ? a&&b && AND ANDROID a-b -a - x"),
            vec![
                (K::Term, r"a\:b"),
                (K::WildcardTerm, "foo*"),
                (K::Star, "*"),
                (K::WildcardTerm, "?"),
                (K::Term, "a&&b"),
                (K::AmpAmp, "&&"),
                (K::AndKw, "AND"),
                (K::Term, "ANDROID"),
                (K::Term, "a-b"),
                (K::Minus, "-"),
                (K::Term, "a"),
                (K::BareOperator, "- "),
                (K::Term, "x"),
            ]
        );
    }

    #[test]
    fn ranges_lex_their_bounds_by_their_own_rules() {
        assert_eq!(
            kinds("a:[1\tTO 2] b:{\"x y\" TO z}^2 TO c:[\t1 TO\n]"),
            vec![
                (K::Term, "a"),
                (K::Colon, ":"),
                (K::LBracket, "["),
                // A tab glues `TO` to the bound: no `TO` follows.
                (K::RangeTerm, "1\tTO"),
                (K::Term, "2"),
                (K::RBracket, "]"),
                (K::Term, "b"),
                (K::Colon, ":"),
                (K::LBrace, "{"),
                (K::Phrase, "\"x y\""),
                (K::ToKw, "TO"),
                (K::RangeTerm, "z"),
                (K::RBrace, "}"),
                (K::Boost, "^2"),
                (K::Term, "TO"),
                (K::Term, "c"),
                (K::Colon, ":"),
                (K::LBracket, "["),
                (K::RangeTerm, "\t1"),
                (K::ToKw, "TO"),
                (K::RangeTerm, "\n"),
                (K::RBracket, "]"),
            ]
        );
        assert_eq!(kinds("[TO TO TO]")[1].0, K::RangeTerm);
        assert_eq!(kinds("[1 TO2]")[2].0, K::Term);
    }

    #[test]
    fn suffixes_regexps_and_errors() {
        assert_eq!(
            kinds(r"a~2 b^1.5 /x\/y/ /a/ ^ \ "),
            vec![
                (K::Term, "a"),
                (K::Fuzzy, "~2"),
                (K::Term, "b"),
                (K::Boost, "^1.5"),
                (K::Regexp, r"/x\/y/"),
                (K::Regexp, "/a/"),
                (K::ErrorToken, "^"),
                (K::Term, r"\ "),
            ]
        );
        assert_eq!(kinds("\"abc")[0].0, K::ErrorToken);
        assert_eq!(kinds("a\\")[1].0, K::ErrorToken);
        assert_eq!(kinds("/ab")[0].0, K::ErrorToken);
    }

    #[test]
    fn every_kind_round_trips_and_token_kinds_fit_a_set() {
        for (i, kind) in ALL.iter().enumerate() {
            assert_eq!(usize::from(kind.raw().0), i);
            assert_eq!(SyntaxKind::from_raw(kind.raw()), *kind);
        }
        assert!(usize::from(TokenSet::CAPACITY) > ALL.len());
    }

    #[test]
    fn the_keywords_table_is_what_the_lexer_cuts() {
        // Each token of `opentide_highlight::keywords(Lucene)` lexes as one
        // token of a kind the highlighter colours with that capture.
        let table = opentide_highlight::keywords(opentide_core::LanguageId::Lucene)
            .expect("Lucene has a KEYWORDS table");
        for (token, capture) in table {
            let (source, kind) = match *token {
                "TO" => ("[a TO b]", K::ToKw),
                ":" => ("a:b", K::Colon),
                "(" => ("(a)", K::LParen),
                ")" => ("(a)", K::RParen),
                "[" => ("[a TO b]", K::LBracket),
                "]" => ("[a TO b]", K::RBracket),
                "{" => ("{a TO b}", K::LBrace),
                "}" => ("{a TO b}", K::RBrace),
                other => panic!("no sample for `{other}`"),
            };
            assert!(
                kinds(source).contains(&(kind, *token)),
                "`{token}` in {source}"
            );
            let expected = match kind {
                K::ToKw => "keyword",
                K::Colon => "operator",
                _ => "punctuation.bracket",
            };
            assert_eq!(capture.name(), expected, "`{token}`");
        }
    }

    #[test]
    fn the_lexemes_tile_any_input() {
        for source in [
            "",
            "\\",
            "a\\",
            "[",
            "[ ",
            "a:[1 TO",
            "{\"",
            "/",
            "~\\",
            "^",
            "é*é?",
            "\u{a0}\u{3000}a",
        ] {
            let end = lex(source).last().map_or(0, |l| usize::from(l.range.end()));
            assert_eq!(end, source.len(), "{source:?}");
        }
    }
}
