//! Falco's kinds, lexer and rowan language.
//!
//! The kinds are the names of `grammars/tree-sitter-opentide-falco`'s rules, so
//! the corpus fixtures (`prod:<rule>`) keep naming what they exercise. The
//! lexer is context free: libsinsp and tree-sitter lex a condition by what the
//! grammar expects next (`<5` is an operator and a value after a field, one
//! word in a value), so the lexer cuts the source into small pieces and the
//! parser glues the ones that make a bare string or a field argument.

use logos::Logos;
use opentide_parse::{Lexeme, TokenSet};

/// A token or node of the Falco tree. Token kinds come first, so every one
/// fits a [`TokenSet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub(crate) enum SyntaxKind {
    // Tokens.
    Whitespace,
    QuotedString,
    /// `proc.name`: letters, digits and `_`, with at least one `.`.
    FieldName,
    /// A name without a `.`: a macro, a list, or a word of a bare string.
    Identifier,
    /// `tolower(`, `val(`: the name and its `(`.
    TransformerName,
    Number,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Eq,
    /// Any other character: a piece of a bare string or an operator.
    Other,
    AndKw,
    OrKw,
    NotKw,
    /// A quote that never closes.
    ErrorToken,
    Eof,
    // Nodes.
    SourceFile,
    AppendFragment,
    OrExpression,
    AndExpression,
    NotExpression,
    ParenthesizedExpression,
    MacroReference,
    Comparison,
    Field,
    FieldArgument,
    ArgumentValue,
    FieldTransformer,
    ValueTransformer,
    TransformerList,
    UnaryOperator,
    ComparisonOperator,
    ListOperator,
    OperatorModifier,
    ValueList,
    ListReference,
    BareString,
    Error,
}

use SyntaxKind as K;

/// Every kind, in discriminant order: `from_raw` indexes it.
const ALL: [SyntaxKind; 40] = [
    K::Whitespace,
    K::QuotedString,
    K::FieldName,
    K::Identifier,
    K::TransformerName,
    K::Number,
    K::LParen,
    K::RParen,
    K::LBracket,
    K::RBracket,
    K::Comma,
    K::Eq,
    K::Other,
    K::AndKw,
    K::OrKw,
    K::NotKw,
    K::ErrorToken,
    K::Eof,
    K::SourceFile,
    K::AppendFragment,
    K::OrExpression,
    K::AndExpression,
    K::NotExpression,
    K::ParenthesizedExpression,
    K::MacroReference,
    K::Comparison,
    K::Field,
    K::FieldArgument,
    K::ArgumentValue,
    K::FieldTransformer,
    K::ValueTransformer,
    K::TransformerList,
    K::UnaryOperator,
    K::ComparisonOperator,
    K::ListOperator,
    K::OperatorModifier,
    K::ValueList,
    K::ListReference,
    K::BareString,
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

    /// The name of the kind: the tree-sitter rule's name for the ones the
    /// grammar had, which the corpus gate reads.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            K::Whitespace => "whitespace",
            K::QuotedString => "quoted_string",
            K::FieldName => "field_name",
            K::Identifier => "identifier",
            K::TransformerName => "transformer_name",
            K::Number => "number",
            K::LParen => "(",
            K::RParen => ")",
            K::LBracket => "[",
            K::RBracket => "]",
            K::Comma => ",",
            K::Eq => "=",
            K::Other => "other",
            K::AndKw => "and",
            K::OrKw => "or",
            K::NotKw => "not",
            K::ErrorToken => "error_token",
            K::Eof => "end of input",
            K::SourceFile => "source_file",
            K::AppendFragment => "append_fragment",
            K::OrExpression => "or_expression",
            K::AndExpression => "and_expression",
            K::NotExpression => "not_expression",
            K::ParenthesizedExpression => "parenthesized_expression",
            K::MacroReference => "macro_reference",
            K::Comparison => "comparison",
            K::Field => "field",
            K::FieldArgument => "field_argument",
            K::ArgumentValue => "argument_value",
            K::FieldTransformer => "field_transformer",
            K::ValueTransformer => "value_transformer",
            K::TransformerList => "transformer_list",
            K::UnaryOperator => "unary_operator",
            K::ComparisonOperator => "comparison_operator",
            K::ListOperator => "list_operator",
            K::OperatorModifier => "operator_modifier",
            K::ValueList => "value_list",
            K::ListReference => "list_reference",
            K::BareString => "bare_string",
            K::Error => "ERROR",
        }
    }
}

/// The rowan language of Falco conditions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Falco {}

impl rowan::Language for Falco {
    type Kind = SyntaxKind;
    fn kind_from_raw(raw: rowan::SyntaxKind) -> SyntaxKind {
        SyntaxKind::from_raw(raw)
    }
    fn kind_to_raw(kind: SyntaxKind) -> rowan::SyntaxKind {
        kind.raw()
    }
}

/// A node of the tree.
pub(crate) type SyntaxNode = rowan::SyntaxNode<Falco>;
/// A token of the tree.
pub(crate) type SyntaxToken = rowan::SyntaxToken<Falco>;

/// The transformers libsinsp lexes together with their `(`.
const TRANSFORMERS: [&str; 9] = [
    "tolower", "toupper", "b64", "basename", "len", "join", "concat", "getopt", "val",
];

/// The lexer. Whitespace is the grammar's `extras`: the blanks libsinsp
/// reads, plus the form feed.
#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    #[regex(r"[ \t\r\n\x0c\x08]+")]
    Whitespace,
    #[token("\"", |lex| quoted(lex, b'"'))]
    #[token("'", |lex| quoted(lex, b'\''))]
    QuotedString,
    /// A name, its `.name` parts, and a transformer's `(`: scanned by a loop
    /// ([`word`]), not a repeated group (see the crate's `tests/long_runs.rs`).
    #[regex(r"[A-Za-z][A-Za-z0-9_]*", word)]
    Word,
    #[regex(r"0[xX][0-9a-fA-F]+")]
    #[regex(r"[+-]?[0-9]+(\.[0-9]*)?([eE][+-][0-9]+)?")]
    Number,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,
    #[token(",")]
    Comma,
    #[token("=")]
    Eq,
    #[regex("[^ \t\r\n\x0c\x08\"'()\\[\\],=A-Za-z0-9]")]
    Other,
}

/// The rest of a name: `.part` groups, then the `(` of a transformer.
fn word(lex: &mut logos::Lexer<'_, Token>) {
    let mut taken = 0;
    loop {
        let rest = lex.remainder().as_bytes();
        let Some((&b'.', after)) = rest.get(taken..).and_then(<[u8]>::split_first) else {
            break;
        };
        if !after.first().is_some_and(u8::is_ascii_alphabetic) {
            break;
        }
        let part = after
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
            .count();
        taken += 1 + part;
    }
    lex.bump(taken);
    let name = lex.slice();
    if lex.remainder().starts_with('(') && TRANSFORMERS.contains(&name) {
        lex.bump(1);
    }
}

/// The rest of a quoted string after its opening `delimiter`: a delimiter
/// closes it unless a backslash comes right before it (libsinsp's `prev`,
/// which starts as a backslash, so `""` is a string and `"\"` is not).
/// Scanned by a loop for the reason of [`word`]. Unclosed, the quote alone is
/// an error.
fn quoted(lex: &mut logos::Lexer<'_, Token>, delimiter: u8) -> bool {
    let mut prev = delimiter;
    for (i, b) in lex.remainder().bytes().enumerate() {
        if b == delimiter && prev != b'\\' {
            lex.bump(i + 1);
            return true;
        }
        prev = b;
    }
    false
}

/// Lexes `source`.
pub(crate) fn lex(source: &str) -> Vec<Lexeme> {
    opentide_parse::lex::<Token>(source, |token, text| {
        match token {
            Ok(Token::Whitespace) => K::Whitespace,
            Ok(Token::QuotedString) => K::QuotedString,
            Ok(Token::Word) => {
                if text.ends_with('(') {
                    K::TransformerName
                } else if text.contains('.') {
                    K::FieldName
                } else {
                    K::Identifier
                }
            }
            Ok(Token::Number) => K::Number,
            Ok(Token::LParen) => K::LParen,
            Ok(Token::RParen) => K::RParen,
            Ok(Token::LBracket) => K::LBracket,
            Ok(Token::RBracket) => K::RBracket,
            Ok(Token::Comma) => K::Comma,
            Ok(Token::Eq) => K::Eq,
            Ok(Token::Other) => K::Other,
            Err(()) => K::ErrorToken,
        }
        .raw()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<(SyntaxKind, &str)> {
        lex(source)
            .iter()
            .map(|l| (SyntaxKind::from_raw(l.kind), &source[l.range]))
            .collect()
    }

    #[test]
    fn names_numbers_and_transformers() {
        assert_eq!(
            kinds("proc.aname[2] tolower(x) len a.b. 0x1F -1.5e+3"),
            vec![
                (K::FieldName, "proc.aname"),
                (K::LBracket, "["),
                (K::Number, "2"),
                (K::RBracket, "]"),
                (K::Whitespace, " "),
                (K::TransformerName, "tolower("),
                (K::Identifier, "x"),
                (K::RParen, ")"),
                (K::Whitespace, " "),
                (K::Identifier, "len"),
                (K::Whitespace, " "),
                (K::FieldName, "a.b"),
                (K::Other, "."),
                (K::Whitespace, " "),
                (K::Number, "0x1F"),
                (K::Whitespace, " "),
                (K::Number, "-1.5e+3"),
            ]
        );
        // `xtolower(` is one word, not a transformer.
        assert_eq!(kinds("xtolower(")[0], (K::Identifier, "xtolower"));
    }

    #[test]
    fn quotes_close_unless_escaped() {
        assert_eq!(kinds(r#""a\"b" 'c'"#)[0], (K::QuotedString, r#""a\"b""#));
        assert_eq!(kinds(r#""""#), vec![(K::QuotedString, r#""""#)]);
        // libsinsp: a quote after a backslash never closes, even `"\\"`.
        assert_eq!(kinds(r#""a\\""#)[0].0, K::ErrorToken);
        assert_eq!(kinds("\"abc")[0].0, K::ErrorToken);
        assert_eq!(kinds("'it's'")[0], (K::QuotedString, "'it'"));
    }

    #[test]
    fn every_kind_round_trips_and_token_kinds_fit_a_set() {
        for (i, kind) in ALL.iter().enumerate() {
            assert_eq!(usize::from(kind.raw().0), i);
            assert_eq!(SyntaxKind::from_raw(kind.raw()), *kind);
        }
        assert!(usize::from(TokenSet::CAPACITY) > ALL.len());
    }
}
