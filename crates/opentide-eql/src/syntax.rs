//! The kinds of an EQL tree and its rowan language: the tokens the lexer cuts, the keywords the
//! parser re-kinds words as, and the nodes of the grammar.
//!
//! The lexer reads every `[A-Za-z_@][A-Za-z0-9_]*` as [`SyntaxKind::WORD`] and every
//! `[A-Za-z][A-Za-z0-9_]*~` as [`SyntaxKind::TILDE_WORD`]; the parser re-kinds the ones its
//! grammar expects as keywords. Elasticsearch reserves every keyword, in lower case only.

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
        // Exported, clippy leaves the acronyms alone; included by path in a test, it does not.
        #[allow(
            clippy::upper_case_acronyms,
            reason = "the kinds are written as rust-analyzer's are, and named by the ungram"
        )]
        pub enum SyntaxKind {
            $($token,)* $($node,)*
        }

        /// Every kind, in declaration order.
        const ALL: &[SyntaxKind] = &[$(SyntaxKind::$token,)* $(SyntaxKind::$node,)*];
    };
}

kinds! {
    tokens: [
        // Trivia.
        WHITESPACE, LINE_COMMENT, BLOCK_COMMENT,
        // Words and literals. `WORD` is an identifier or a keyword; `TILDE_WORD` is a name
        // ending in `~` (`stringcontains~`, and the `in~`, `like~` and `regex~` operators);
        // `INDEX_TOKEN` is `[0]`; `STRING_TOKEN` is any of the five string forms.
        WORD, TILDE_WORD, NUMBER_TOKEN, STRING_TOKEN, QUOTED_IDENT_TOKEN, INDEX_TOKEN,
        // Keywords: never lexed, the parser re-kinds a word.
        AND_KW, ANY_KW, BY_KW, FALSE_KW, IN_KW, JOIN_KW, LIKE_KW, MAXSPAN_KW, NOT_KW, NULL_KW,
        OF_KW, OR_KW, REGEX_KW, SAMPLE_KW, SEQUENCE_KW, TRUE_KW, UNTIL_KW, WHERE_KW, WITH_KW,
        // The case-insensitive operators: a `TILDE_WORD` the parser re-kinds.
        IN_TILDE, LIKE_TILDE, REGEX_TILDE,
        // Punctuation and operators.
        PIPE, EQ, EQ_EQ, NOT_EQ, LT, LT_EQ, GT, GT_EQ, PLUS, MINUS, STAR, SLASH, PERCENT,
        L_PAREN, R_PAREN, L_BRACK, R_BRACK, BANG_L_BRACK, COMMA, DOT, COLON, QUESTION,
        // A character no token takes.
        ERROR_TOKEN,
        // Past the last token.
        EOF,
    ],
    nodes: [
        ERROR,
        // One per node of `eql.ungram`, named as tree-sitter's (`PIPE_STAGE` is its `pipe`).
        SOURCE_FILE,
        EVENT_QUERY, ANY, EVENT_CATEGORY, SEQUENCE, SEQUENCE_PARAMS, TIME_UNIT, SAMPLE, JOIN,
        JOIN_KEYS, JOIN_TERM, SEQUENCE_TERM, TERM_OPTION, SUBQUERY, MISSING_EVENT_OPEN,
        PIPE_STAGE,
        OR_EXPRESSION, AND_EXPRESSION, NOT_EXPRESSION, RELATIONSHIP, COMPARISON,
        UNARY_EXPRESSION, BINARY_EXPRESSION, PREDICATE_EXPRESSION, PARENTHESIZED_EXPRESSION,
        FUNCTION_CALL, CASE_INSENSITIVE_NAME, FIELD, OPTIONAL_MARKER, INDEX, IDENTIFIER,
        QUOTED_IDENTIFIER, NULL, BOOLEAN, NUMBER, STRING,
    ],
}

impl SyntaxKind {
    /// The raw rowan kind.
    pub const fn raw(self) -> rowan::SyntaxKind {
        rowan::SyntaxKind(self as u16)
    }

    /// Whitespace or a comment.
    pub const fn is_trivia(self) -> bool {
        matches!(
            self,
            Self::WHITESPACE | Self::LINE_COMMENT | Self::BLOCK_COMMENT
        )
    }

    /// The kind of a raw rowan kind (`ERROR` for one that is none of ours).
    pub fn from_raw(raw: rowan::SyntaxKind) -> Self {
        ALL.get(usize::from(raw.0)).copied().unwrap_or(Self::ERROR)
    }

    /// How an error message spells a token the parser expected; `""` for a kind a message
    /// never names.
    pub fn describe(self) -> &'static str {
        match self {
            Self::WORD => "a name",
            Self::TILDE_WORD => "a function",
            Self::NUMBER_TOKEN => "a number",
            Self::STRING_TOKEN => "a string",
            Self::QUOTED_IDENT_TOKEN => "a quoted name",
            Self::INDEX_TOKEN => "an index",
            Self::AND_KW => "`and`",
            Self::ANY_KW => "`any`",
            Self::BY_KW => "`by`",
            Self::FALSE_KW => "`false`",
            Self::IN_KW => "`in`",
            Self::JOIN_KW => "`join`",
            Self::LIKE_KW => "`like`",
            Self::MAXSPAN_KW => "`maxspan`",
            Self::NOT_KW => "`not`",
            Self::NULL_KW => "`null`",
            Self::OF_KW => "`of`",
            Self::OR_KW => "`or`",
            Self::REGEX_KW => "`regex`",
            Self::SAMPLE_KW => "`sample`",
            Self::SEQUENCE_KW => "`sequence`",
            Self::TRUE_KW => "`true`",
            Self::UNTIL_KW => "`until`",
            Self::WHERE_KW => "`where`",
            Self::WITH_KW => "`with`",
            Self::IN_TILDE => "`in~`",
            Self::LIKE_TILDE => "`like~`",
            Self::REGEX_TILDE => "`regex~`",
            Self::PIPE => "`|`",
            Self::EQ => "`=`",
            Self::EQ_EQ => "`==`",
            Self::NOT_EQ => "`!=`",
            Self::LT => "`<`",
            Self::LT_EQ => "`<=`",
            Self::GT => "`>`",
            Self::GT_EQ => "`>=`",
            Self::PLUS => "`+`",
            Self::MINUS => "`-`",
            Self::STAR => "`*`",
            Self::SLASH => "`/`",
            Self::PERCENT => "`%`",
            Self::L_PAREN => "`(`",
            Self::R_PAREN => "`)`",
            Self::L_BRACK => "`[`",
            Self::R_BRACK => "`]`",
            Self::BANG_L_BRACK => "`![`",
            Self::COMMA => "`,`",
            Self::DOT => "`.`",
            Self::COLON => "`:`",
            Self::QUESTION => "`?`",
            Self::EOF => "end of input",
            _ => "",
        }
    }

    /// A set of token kinds.
    pub const fn set(kinds: &[Self]) -> TokenSet {
        let mut set = TokenSet::EMPTY;
        let mut i = 0;
        while i < kinds.len() {
            set = set.with(kinds[i].raw());
            i += 1;
        }
        set
    }
}

/// The rowan language of EQL.
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

/// A node of an EQL tree.
pub type SyntaxNode = rowan::SyntaxNode<Lang>;

/// A token of an EQL tree.
#[allow(
    dead_code,
    reason = "the typed AST (src/generated/ast.rs) uses it; the analysis does not yet"
)]
pub type SyntaxToken = rowan::SyntaxToken<Lang>;

/// The kind of each token of `eql.ungram`.
#[macro_export]
macro_rules! T {
    [and] => { $crate::SyntaxKind::AND_KW };
    [any] => { $crate::SyntaxKind::ANY_KW };
    [by] => { $crate::SyntaxKind::BY_KW };
    [false] => { $crate::SyntaxKind::FALSE_KW };
    [in] => { $crate::SyntaxKind::IN_KW };
    [join] => { $crate::SyntaxKind::JOIN_KW };
    [like] => { $crate::SyntaxKind::LIKE_KW };
    [maxspan] => { $crate::SyntaxKind::MAXSPAN_KW };
    [not] => { $crate::SyntaxKind::NOT_KW };
    [null] => { $crate::SyntaxKind::NULL_KW };
    [of] => { $crate::SyntaxKind::OF_KW };
    [or] => { $crate::SyntaxKind::OR_KW };
    [regex] => { $crate::SyntaxKind::REGEX_KW };
    [sample] => { $crate::SyntaxKind::SAMPLE_KW };
    [sequence] => { $crate::SyntaxKind::SEQUENCE_KW };
    [true] => { $crate::SyntaxKind::TRUE_KW };
    [until] => { $crate::SyntaxKind::UNTIL_KW };
    [where] => { $crate::SyntaxKind::WHERE_KW };
    [with] => { $crate::SyntaxKind::WITH_KW };
    [word] => { $crate::SyntaxKind::WORD };
    [number] => { $crate::SyntaxKind::NUMBER_TOKEN };
    [string] => { $crate::SyntaxKind::STRING_TOKEN };
    [quoted_ident] => { $crate::SyntaxKind::QUOTED_IDENT_TOKEN };
    [index] => { $crate::SyntaxKind::INDEX_TOKEN };
    [tilde_word] => { $crate::SyntaxKind::TILDE_WORD };
    [in~] => { $crate::SyntaxKind::IN_TILDE };
    [like~] => { $crate::SyntaxKind::LIKE_TILDE };
    [regex~] => { $crate::SyntaxKind::REGEX_TILDE };
    [|] => { $crate::SyntaxKind::PIPE };
    [=] => { $crate::SyntaxKind::EQ };
    [==] => { $crate::SyntaxKind::EQ_EQ };
    [!=] => { $crate::SyntaxKind::NOT_EQ };
    [<] => { $crate::SyntaxKind::LT };
    [<=] => { $crate::SyntaxKind::LT_EQ };
    [>] => { $crate::SyntaxKind::GT };
    [>=] => { $crate::SyntaxKind::GT_EQ };
    [+] => { $crate::SyntaxKind::PLUS };
    [-] => { $crate::SyntaxKind::MINUS };
    [*] => { $crate::SyntaxKind::STAR };
    [/] => { $crate::SyntaxKind::SLASH };
    [%] => { $crate::SyntaxKind::PERCENT };
    ['('] => { $crate::SyntaxKind::L_PAREN };
    [')'] => { $crate::SyntaxKind::R_PAREN };
    ['['] => { $crate::SyntaxKind::L_BRACK };
    [']'] => { $crate::SyntaxKind::R_BRACK };
    [bang_l_brack] => { $crate::SyntaxKind::BANG_L_BRACK };
    [,] => { $crate::SyntaxKind::COMMA };
    [.] => { $crate::SyntaxKind::DOT };
    [:] => { $crate::SyntaxKind::COLON };
    [?] => { $crate::SyntaxKind::QUESTION };
}

/// The `Debug` names of the node kinds, the error node left out (`debug_node_kinds`).
pub fn node_kinds() -> Vec<String> {
    ALL.iter()
        .filter(|k| **k >= SyntaxKind::SOURCE_FILE && **k != SyntaxKind::ERROR)
        .map(|k| format!("{k:?}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_token_kind_fits_a_token_set() {
        assert!(usize::from(SyntaxKind::EOF.raw().0) < usize::from(TokenSet::CAPACITY));
        assert_eq!(
            <Lang as rowan::Language>::kind_from_raw(SyntaxKind::SOURCE_FILE.raw()),
            SyntaxKind::SOURCE_FILE
        );
    }
}
