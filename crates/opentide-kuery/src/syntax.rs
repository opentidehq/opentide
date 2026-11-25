//! Kibana KQL's kinds, lexer and rowan language.

use logos::Logos;
use opentide_parse::{Lexeme, TokenSet};

/// A token or node of the Kibana KQL tree (the tree-sitter grammar's names).
/// Token kinds come first, so every one fits a [`TokenSet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub(crate) enum SyntaxKind {
    // Tokens.
    Whitespace,
    Word,
    QuotedString,
    OrKw,
    AndKw,
    NotKw,
    Colon,
    Lt,
    Lte,
    Gt,
    Gte,
    LParen,
    RParen,
    LBrace,
    RBrace,
    /// A character no token takes (a lone `\`, an unclosed `"`).
    ErrorToken,
    Eof,
    // Nodes.
    SourceFile,
    OrQuery,
    AndQuery,
    NotQuery,
    Group,
    NestedQuery,
    RangeExpression,
    FieldValueExpression,
    ValueExpression,
    ValueList,
    OrList,
    AndList,
    NotList,
    Field,
    UnquotedLiteral,
    Error,
}

use SyntaxKind as K;

/// Every kind, in discriminant order: `kind_from_raw` indexes it.
const ALL: [SyntaxKind; 33] = [
    K::Whitespace,
    K::Word,
    K::QuotedString,
    K::OrKw,
    K::AndKw,
    K::NotKw,
    K::Colon,
    K::Lt,
    K::Lte,
    K::Gt,
    K::Gte,
    K::LParen,
    K::RParen,
    K::LBrace,
    K::RBrace,
    K::ErrorToken,
    K::Eof,
    K::SourceFile,
    K::OrQuery,
    K::AndQuery,
    K::NotQuery,
    K::Group,
    K::NestedQuery,
    K::RangeExpression,
    K::FieldValueExpression,
    K::ValueExpression,
    K::ValueList,
    K::OrList,
    K::AndList,
    K::NotList,
    K::Field,
    K::UnquotedLiteral,
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

    /// How an error message spells a token the parser expected; `""` for a
    /// kind a message never names.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            K::Word | K::QuotedString => "a value",
            K::OrKw => "`or`",
            K::AndKw => "`and`",
            K::NotKw => "`not`",
            K::Colon => "`:`",
            K::Lt | K::Lte | K::Gt | K::Gte => "a range operator",
            K::LParen => "`(`",
            K::RParen => "`)`",
            K::LBrace => "`{`",
            K::RBrace => "`}`",
            K::Eof => "end of input",
            _ => "",
        }
    }
}

/// The rowan language of Kibana KQL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Kuery {}

impl rowan::Language for Kuery {
    type Kind = SyntaxKind;
    fn kind_from_raw(raw: rowan::SyntaxKind) -> SyntaxKind {
        SyntaxKind::from_raw(raw)
    }
    fn kind_to_raw(kind: SyntaxKind) -> rowan::SyntaxKind {
        kind.raw()
    }
}

/// A node of the tree.
pub(crate) type SyntaxNode = rowan::SyntaxNode<Kuery>;
/// A token of the tree.
pub(crate) type SyntaxToken = rowan::SyntaxToken<Kuery>;
/// A node or a token.
pub(crate) type SyntaxElement = rowan::SyntaxElement<Kuery>;

/// The lexer: the grammar's `word` is a run of characters other than
/// whitespace and `\():<>"{}`, or Kibana's escapes; whitespace includes NBSP.
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    #[regex(r"[ \t\r\n\u{00A0}]+")]
    Whitespace,
    #[token("\"", quoted)]
    QuotedString,
    #[regex(
        r#"[^ \t\r\n\u{00A0}\\():<>"{}]|\\[\\():<>"*{}trn]|\\u[0-9a-fA-F]{4}|\\[aA][nN][dD]|\\[oO][rR]|\\[nN][oO][tT]"#,
        word
    )]
    Word,
    #[token(":")]
    Colon,
    #[token("<")]
    Lt,
    #[token("<=")]
    Lte,
    #[token(">")]
    Gt,
    #[token(">=")]
    Gte,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
}

/// The length of the word unit at the start of `rest` (one character, or
/// one of Kibana's escapes), or 0 when none starts there.
fn word_unit(rest: &str) -> usize {
    let mut chars = rest.chars();
    let Some(c) = chars.next() else { return 0 };
    if !matches!(
        c,
        ' ' | '\t' | '\r' | '\n' | '\u{a0}' | '\\' | '(' | ')' | ':' | '<' | '>' | '"' | '{' | '}'
    ) {
        return c.len_utf8();
    }
    if c != '\\' {
        return 0;
    }
    let after = &rest[1..];
    let Some(e) = after.chars().next() else {
        return 0;
    };
    if matches!(
        e,
        '\\' | '(' | ')' | ':' | '<' | '>' | '"' | '*' | '{' | '}' | 't' | 'r' | 'n'
    ) {
        return 1 + e.len_utf8();
    }
    let bytes = after.as_bytes();
    if e == 'u'
        && bytes
            .get(1..5)
            .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit))
    {
        return 6;
    }
    for word in ["and", "or", "not"] {
        if after
            .get(..word.len())
            .is_some_and(|w| w.eq_ignore_ascii_case(word))
        {
            return 1 + word.len();
        }
    }
    0
}

/// A word is a run of units. Scanned by a loop: a repeated regex group
/// makes logos recurse once per unit and overflows the stack on a long run
/// of escapes (`\:` x 3000).
fn word(lex: &mut logos::Lexer<'_, Token>) {
    // The first unit is already matched; take the longest run after it.
    let mut taken = 0;
    loop {
        let n = word_unit(&lex.remainder()[taken..]);
        if n == 0 {
            break;
        }
        taken += n;
    }
    lex.bump(taken);
}

/// The rest of a quoted string after its `"`: any character but `"` and
/// `\\`, or `\\` and one character but a newline, then `"`. Unclosed, the
/// `"` alone is an error. Scanned by a loop for the reason of [`word`].
fn quoted(lex: &mut logos::Lexer<'_, Token>) -> bool {
    let mut chars = lex.remainder().char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => {
                lex.bump(i + 1);
                return true;
            }
            '\\' => match chars.next() {
                Some((_, '\n')) | None => return false,
                Some(_) => {}
            },
            _ => {}
        }
    }
    false
}

/// Lexes `source`. A word spelled `or`, `and` or `not` (any case) becomes
/// a keyword candidate, which the parser reads as a word where Kibana's
/// grammar has no keyword. With `mask`, one that ends the query or sits
/// directly before `)` or `}` stays a word: Kibana reads it as value text.
pub(crate) fn lex(source: &str, mask: bool) -> Vec<Lexeme> {
    let mut lexemes = opentide_parse::lex::<Token>(source, |token, text| {
        match token {
            Ok(Token::Whitespace) => K::Whitespace,
            Ok(Token::QuotedString) => K::QuotedString,
            Ok(Token::Word) => {
                if text.eq_ignore_ascii_case("or") {
                    K::OrKw
                } else if text.eq_ignore_ascii_case("and") {
                    K::AndKw
                } else if text.eq_ignore_ascii_case("not") {
                    K::NotKw
                } else {
                    K::Word
                }
            }
            Ok(Token::Colon) => K::Colon,
            Ok(Token::Lt) => K::Lt,
            Ok(Token::Lte) => K::Lte,
            Ok(Token::Gt) => K::Gt,
            Ok(Token::Gte) => K::Gte,
            Ok(Token::LParen) => K::LParen,
            Ok(Token::RParen) => K::RParen,
            Ok(Token::LBrace) => K::LBrace,
            Ok(Token::RBrace) => K::RBrace,
            Err(()) => K::ErrorToken,
        }
        .raw()
    });
    if mask {
        let bytes = source.as_bytes();
        for l in &mut lexemes {
            let keyword = [K::OrKw, K::AndKw, K::NotKw].map(K::raw).contains(&l.kind);
            let next = bytes.get(usize::from(l.range.end())).copied();
            if keyword && matches!(next, None | Some(b')' | b'}')) {
                l.kind = K::Word.raw();
            }
        }
    }
    lexemes
}

/// The `Debug` names of the node kinds, the error node left out (`debug_node_kinds`).
pub(crate) fn node_kinds() -> Vec<String> {
    ALL.iter()
        .filter(|k| **k >= SyntaxKind::SourceFile && **k != SyntaxKind::Error)
        .map(|k| format!("{k:?}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<(SyntaxKind, &str)> {
        lex(source, true)
            .iter()
            .map(|l| (SyntaxKind::from_raw(l.kind), &source[l.range]))
            .collect()
    }

    #[test]
    fn words_escapes_and_errors() {
        assert_eq!(
            kinds(r#"a\:b <= "x\"y" ab\u12 or"#),
            vec![
                (K::Word, r"a\:b"),
                (K::Whitespace, " "),
                (K::Lte, "<="),
                (K::Whitespace, " "),
                (K::QuotedString, r#""x\"y""#),
                (K::Whitespace, " "),
                (K::Word, "ab"),
                (K::ErrorToken, r"\"),
                (K::Word, "u12"),
                (K::Whitespace, " "),
                (K::Word, "or"),
            ]
        );
        assert_eq!(kinds(r"\not"), vec![(K::Word, r"\not")]);
        assert_eq!(kinds("a or b")[2].0, K::OrKw);
        assert_eq!(kinds("\"abc")[0].0, K::ErrorToken);
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
    fn a_keyword_before_a_closer_or_the_end_is_masked_only_when_asked() {
        let masked = |s: &str, mask: bool| SyntaxKind::from_raw(lex(s, mask)[4].kind);
        assert_eq!(masked("f:a or", true), K::Word);
        assert_eq!(masked("f:a or", false), K::OrKw);
        assert_eq!(masked("f:a or)", true), K::Word);
        assert_eq!(masked("f:a or ", true), K::OrKw);
    }
}
