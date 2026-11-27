//! The kinds of a Datadog search tree and its rowan language: the tokens the lexer cuts, the
//! kinds the parser re-kinds a token as, and one node per named production of `datadog.ungram`.
//!
//! The lexer reads every run of term characters as [`SyntaxKind::WORD`]. The parser re-kinds
//! the words its grammar gives a meaning: `AND`, `OR`, `NOT` and `TO` (upper case only), `&&`
//! and `||` where an operator stands, `CIDR` before `(`, and a word that is a number (with an
//! optional duration unit) where it is a whole value.

use opentide_parse::TokenSet;

macro_rules! kinds {
    (
        tokens: [$($token:ident),* $(,)?],
        nodes: [$($node:ident),* $(,)?] $(,)?
    ) => {
        /// A token or node kind. Tokens come first (below `TokenSet::CAPACITY`).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u16)]
        #[expect(
            non_camel_case_types,
            reason = "the kinds are written as rust-analyzer's are, and named by the ungram"
        )]
        pub enum SyntaxKind {
            $(
                #[doc = concat!("The token `", stringify!($token), "`.")]
                $token,
            )*
            $(
                #[doc = concat!("The node `", stringify!($node), "`.")]
                $node,
            )*
        }

        /// Every kind, in declaration order.
        const ALL: &[SyntaxKind] = &[$(SyntaxKind::$token,)* $(SyntaxKind::$node,)*];

        /// The node kinds, in declaration order.
        const NODES: &[SyntaxKind] = &[$(SyntaxKind::$node,)*];
    };
}

kinds! {
    tokens: [
        // Trivia: spaces, tabs, line breaks (and a byte-order mark).
        WHITESPACE,
        // A run of term characters; `NUMBER` is a word the parser read as a number.
        WORD, NUMBER,
        // `\` and the character after it.
        ESCAPE,
        // `"…"`, and a `"` with no closing quote (it runs to the end of the text).
        PHRASE_TOKEN, UNCLOSED_PHRASE,
        // Punctuation and operators.
        STAR, QUESTION, COLON, COMMA, MINUS, PLUS, EQ, BANG, TILDE, CARET, LT, LT_EQ, GT, GT_EQ,
        L_PAREN, R_PAREN, L_BRACK, R_BRACK, L_BRACE, R_BRACE,
        // Never lexed: the parser re-kinds a word.
        AND_KW, OR_KW, NOT_KW, TO_KW, CIDR_KW, AMP_AMP, PIPE_PIPE,
        // A character no token takes: a backslash at the end of the text.
        ERROR_TOKEN,
        // Past the last token.
        EOF,
    ],
    nodes: [
        ERROR,
        QUERY, OR_EXPR, AND_EXPR, NOT_EXPR, GROUP, MATCH_ALL, CIDR_CALL, CIDR_BLOCK,
        FIELD_CLAUSE, ATTRIBUTE, CALCULATED_FIELD, TAG_KEY, ALL_ATTRIBUTES, QUOTED_FIELD,
        VALUE_GROUP, VALUE_OR_EXPR, VALUE_AND_EXPR, VALUE_NOT_EXPR,
        TERM, PHRASE, COMPARISON, RANGE, RANGE_BOUND,
    ],
}

impl SyntaxKind {
    /// The raw rowan kind.
    #[must_use]
    pub const fn raw(self) -> rowan::SyntaxKind {
        rowan::SyntaxKind(self as u16)
    }

    /// The kind of a raw rowan kind (`ERROR` for one that is none of ours).
    #[must_use]
    pub fn from_raw(raw: rowan::SyntaxKind) -> Self {
        ALL.get(usize::from(raw.0)).copied().unwrap_or(Self::ERROR)
    }

    /// A set of token kinds.
    #[must_use]
    pub const fn set(kinds: &[Self]) -> TokenSet {
        let mut set = TokenSet::EMPTY;
        let mut i = 0;
        while i < kinds.len() {
            set = set.with(kinds[i].raw());
            i += 1;
        }
        set
    }

    /// Whether a value of this kind may follow on from the token before it with no space
    /// between: the characters a term, a value or a field glues together.
    pub(crate) fn is_term_piece(self) -> bool {
        TERM_PIECES.contains(self.raw())
    }
}

/// The tokens a term is made of when they touch: `web-*`, `waiting\ un*`, `a:b:c` (in a value),
/// `foo!bar` (refused by a check, not by the grammar), `service\:"web-store"`.
pub(crate) const TERM_PIECES: TokenSet = SyntaxKind::set(&[
    SyntaxKind::WORD,
    SyntaxKind::NUMBER,
    SyntaxKind::ESCAPE,
    SyntaxKind::STAR,
    SyntaxKind::QUESTION,
    SyntaxKind::COLON,
    SyntaxKind::COMMA,
    SyntaxKind::MINUS,
    SyntaxKind::PLUS,
    SyntaxKind::EQ,
    SyntaxKind::BANG,
    SyntaxKind::TILDE,
    SyntaxKind::CARET,
    SyntaxKind::LT,
    SyntaxKind::LT_EQ,
    SyntaxKind::GT,
    SyntaxKind::GT_EQ,
    SyntaxKind::PHRASE_TOKEN,
    SyntaxKind::UNCLOSED_PHRASE,
]);

/// The `snake_case` name of `kind` (`FIELD_CLAUSE` is `field_clause`): what the corpus gate tags.
pub(crate) fn snake_case(kind: SyntaxKind) -> String {
    format!("{kind:?}").to_ascii_lowercase()
}

/// The `snake_case` names of the node kinds, the error node left out: the productions the
/// corpus gate asks a fixture of.
pub(crate) fn node_kinds() -> Vec<String> {
    NODES
        .iter()
        .filter(|&&k| k != SyntaxKind::ERROR)
        .map(|&k| snake_case(k))
        .collect()
}

/// The rowan language of the Datadog search syntax.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lang {}

impl rowan::Language for Lang {
    type Kind = SyntaxKind;
    fn kind_from_raw(raw: rowan::SyntaxKind) -> SyntaxKind {
        SyntaxKind::from_raw(raw)
    }
    fn kind_to_raw(kind: SyntaxKind) -> rowan::SyntaxKind {
        kind.raw()
    }
}

/// A node of the tree.
pub type SyntaxNode = rowan::SyntaxNode<Lang>;
/// A token of the tree.
pub type SyntaxToken = rowan::SyntaxToken<Lang>;

/// The kind of each token of `datadog.ungram`.
#[macro_export]
macro_rules! T {
    [word] => { $crate::SyntaxKind::WORD };
    [number] => { $crate::SyntaxKind::NUMBER };
    [escape] => { $crate::SyntaxKind::ESCAPE };
    [phrase] => { $crate::SyntaxKind::PHRASE_TOKEN };
    [unclosed_phrase] => { $crate::SyntaxKind::UNCLOSED_PHRASE };
    [and] => { $crate::SyntaxKind::AND_KW };
    [or] => { $crate::SyntaxKind::OR_KW };
    [not] => { $crate::SyntaxKind::NOT_KW };
    [to] => { $crate::SyntaxKind::TO_KW };
    [cidr] => { $crate::SyntaxKind::CIDR_KW };
    [&&] => { $crate::SyntaxKind::AMP_AMP };
    [||] => { $crate::SyntaxKind::PIPE_PIPE };
    [*] => { $crate::SyntaxKind::STAR };
    [?] => { $crate::SyntaxKind::QUESTION };
    [:] => { $crate::SyntaxKind::COLON };
    [,] => { $crate::SyntaxKind::COMMA };
    [-] => { $crate::SyntaxKind::MINUS };
    [+] => { $crate::SyntaxKind::PLUS };
    [=] => { $crate::SyntaxKind::EQ };
    [!] => { $crate::SyntaxKind::BANG };
    [~] => { $crate::SyntaxKind::TILDE };
    [^] => { $crate::SyntaxKind::CARET };
    [<] => { $crate::SyntaxKind::LT };
    [<=] => { $crate::SyntaxKind::LT_EQ };
    [>] => { $crate::SyntaxKind::GT };
    [>=] => { $crate::SyntaxKind::GT_EQ };
    ['('] => { $crate::SyntaxKind::L_PAREN };
    [')'] => { $crate::SyntaxKind::R_PAREN };
    ['['] => { $crate::SyntaxKind::L_BRACK };
    [']'] => { $crate::SyntaxKind::R_BRACK };
    ['{'] => { $crate::SyntaxKind::L_BRACE };
    ['}'] => { $crate::SyntaxKind::R_BRACE };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_token_kind_fits_a_token_set() {
        assert!(usize::from(SyntaxKind::EOF.raw().0) < usize::from(TokenSet::CAPACITY));
        assert_eq!(
            <Lang as rowan::Language>::kind_from_raw(SyntaxKind::QUERY.raw()),
            SyntaxKind::QUERY
        );
        assert_eq!(NODES.first(), Some(&SyntaxKind::ERROR));
    }
}
