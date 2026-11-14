//! Kibana KQL's kinds, lexer and rowan language.

use logos::Logos;
use opentide_parse::{Lexeme, TokenSet};

/// A token or node of the Kibana KQL tree (the tree-sitter grammar's names).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
#[expect(missing_docs, reason = "the names are the grammar's")]
pub enum SyntaxKind {
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
    pub const fn raw(self) -> rowan::SyntaxKind {
        rowan::SyntaxKind(self as u16)
    }

    /// A set of kinds.
    pub const fn set(kinds: &[SyntaxKind]) -> TokenSet {
        let mut raw = [rowan::SyntaxKind(0); 16];
        let mut i = 0;
        while i < kinds.len() && i < 16 {
            raw[i] = kinds[i].raw();
            i += 1;
        }
        let len = if kinds.len() < 16 { kinds.len() } else { 16 };
        TokenSet::new(raw.split_at(len).0)
    }

    /// How an error message spells a token the parser expected.
    pub fn describe(self) -> &'static str {
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
pub enum Kuery {}

impl rowan::Language for Kuery {
    type Kind = SyntaxKind;
    fn kind_from_raw(raw: rowan::SyntaxKind) -> SyntaxKind {
        ALL.get(usize::from(raw.0)).copied().unwrap_or(K::Error)
    }
    fn kind_to_raw(kind: SyntaxKind) -> rowan::SyntaxKind {
        kind.raw()
    }
}

/// A node of the tree.
pub type SyntaxNode = rowan::SyntaxNode<Kuery>;
/// A token of the tree.
pub type SyntaxToken = rowan::SyntaxToken<Kuery>;
/// A node or a token.
pub type SyntaxElement = rowan::SyntaxElement<Kuery>;

/// The lexer: the grammar's `word` is a run of characters other than
/// whitespace and `\():<>"{}`, or Kibana's escapes; whitespace includes NBSP.
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    #[regex(r"[ \t\r\n\u{00A0}]+")]
    Whitespace,
    #[regex(r#""([^"\\]|\\[^\n])*""#)]
    QuotedString,
    #[regex(r#"([^ \t\r\n\u{00A0}\\():<>"{}]|\\[\\():<>"*{}trn]|\\u[0-9a-fA-F]{4}|\\[aA][nN][dD]|\\[oO][rR]|\\[nN][oO][tT])+"#)]
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

/// Lexes `source`. A word spelled `or`, `and` or `not` (any case) becomes
/// a keyword candidate, which the parser reads as a word where Kibana's
/// grammar has no keyword. With `mask`, one that ends the query or sits
/// before `)` or `}` stays a word: Kibana reads it as value text.
pub fn lex(source: &str, mask: bool) -> Vec<Lexeme> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<(SyntaxKind, &str)> {
        lex(source, true)
            .iter()
            .map(|l| {
                (
                    <Kuery as rowan::Language>::kind_from_raw(l.kind),
                    &source[l.range],
                )
            })
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
}
