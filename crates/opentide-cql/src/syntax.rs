//! The kinds of a CQL tree and its rowan language: the tokens the lexer cuts, the keywords the
//! parser re-kinds words as, and one node per named production of `cql.ungram`.
//!
//! The lexer reads every run of field characters as [`SyntaxKind::WORD`]; the parser re-kinds
//! the ones its grammar expects as keywords (`case`, `match`, `like`, `true`, `false` are
//! contextual, and `and`, `or`, `not` are reserved in any case).

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
        // Words and literals. `WORD` is a run of field characters: a field name, a
        // keyword, an identifier, a bare pattern. `PATTERN` holds `* + - : /` (a scanner
        // token of the tree-sitter grammar); `ASSIGN_FIELD_TOKEN` is the scanner's name before `:=`
        // (any word, keywords included); `PATTERN_ERROR` is one that ends in `//`.
        WORD, ASSIGN_FIELD_TOKEN, PATTERN, PATTERN_ERROR, NUMBER_TOKEN, TAG_TOKEN, STRING_TOKEN,
        FUNCTION_NAME_TOKEN, SAVED_QUERY_NAME_TOKEN, PARAMETER_NAME_TOKEN,
        REGEX_PATTERN_TOKEN, REGEX_FLAGS_TOKEN,
        // Keywords: never lexed, the parser re-kinds a word.
        AND_KW, OR_KW, NOT_KW, CASE_KW, MATCH_KW, LIKE_KW, TRUE_KW, FALSE_KW,
        // Punctuation and operators.
        PIPE, EQ, NOT_EQ, EQ_EQ, LT, LT_EQ, GT, GT_EQ, LT_EQ_GT, COLON_EQ, EQ_TILDE, FAT_ARROW,
        BANG, PLUS, MINUS, STAR, SLASH, PERCENT, L_PAREN, R_PAREN, L_BRACK, R_BRACK, L_BRACE,
        R_BRACE, COMMA, SEMI, COLON, DOLLAR, QUESTION, QUESTION_L_BRACE,
        // A character no token takes.
        ERROR_TOKEN,
        // Past the last token.
        EOF,
    ],
    nodes: [
        ERROR,
        SOURCE_FILE, PIPELINE, STEP, FILTER, AND_FILTER, OR_FILTER, NOT_FILTER,
        PARENTHESIZED_FILTER, FIELD_FILTER, FIELD, FILTER_OPERAND, FREE_TEXT, FREE_TEXT_VALUE,
        FIELD_NAME, UNQUOTED_PATTERN, TAG, STRING, NUMBER, BOOLEAN, AND, OR, NOT, CALL_STEP,
        NEGATED_FUNCTION_CALL, ASSIGNMENT, FIELD_SHORTHAND, STATS_SHORTHAND, LINK_CONSTRAINT,
        CASE_STATEMENT, CASE_BRANCH, MATCH_STATEMENT, MATCH_BRANCH, MATCH_GUARD, SAVED_QUERY,
        SAVED_QUERY_TARGET, SAVED_QUERY_NAME, SAVED_QUERY_ARGUMENT, ARGUMENT_OPERAND,
        ARGUMENT_NAME, QUERY_PARAMETER, PARAMETER_DEFAULT, PARAMETER_TARGET, PARAMETER_OPERAND,
        PARAMETER_NAME, REGEX, REGEX_PATTERN, REGEX_FLAGS, FUNCTION_CALL, FUNCTION_NAME,
        ARGUMENT_LIST, ARGUMENT, NAMED_ARGUMENT, NAMED_ARGUMENT_OPERAND, ATTRIBUTED_EXPR,
        ATTRIBUTED_EXPRESSION, EXPRESSION_ATTRIBUTE, IDENTIFIER, EXPR, BINARY_EXPRESSION,
        UNARY_EXPRESSION, PARENTHESIZED_EXPRESSION, SUBQUERY, NAMED_SUBQUERY, ARRAY,
        ARRAY_ELEMENT,
    ],
}

impl SyntaxKind {
    /// The raw rowan kind.
    pub const fn raw(self) -> rowan::SyntaxKind {
        rowan::SyntaxKind(self as u16)
    }

    /// The kind of a raw rowan kind (`ERROR` for one that is none of ours).
    pub fn from_raw(raw: rowan::SyntaxKind) -> Self {
        ALL.get(usize::from(raw.0)).copied().unwrap_or(Self::ERROR)
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

/// The node kinds a parse builds: one per named production of `cql.ungram` (its enums,
/// such as `Filter` and `Expr`, are no node), and the two comments, which tree-sitter's
/// grammar named. The corpus gate tags each (`prod:<name>`).
pub const PRODUCTIONS: &[SyntaxKind] = {
    use SyntaxKind as K;
    &[
        K::LINE_COMMENT,
        K::BLOCK_COMMENT,
        K::SOURCE_FILE,
        K::PIPELINE,
        K::AND_FILTER,
        K::OR_FILTER,
        K::NOT_FILTER,
        K::PARENTHESIZED_FILTER,
        K::FIELD_FILTER,
        K::FREE_TEXT,
        K::FIELD_NAME,
        K::UNQUOTED_PATTERN,
        K::TAG,
        K::STRING,
        K::NUMBER,
        K::BOOLEAN,
        K::AND,
        K::OR,
        K::NOT,
        K::NEGATED_FUNCTION_CALL,
        K::ASSIGNMENT,
        K::FIELD_SHORTHAND,
        K::STATS_SHORTHAND,
        K::LINK_CONSTRAINT,
        K::CASE_STATEMENT,
        K::CASE_BRANCH,
        K::MATCH_STATEMENT,
        K::MATCH_BRANCH,
        K::SAVED_QUERY,
        K::SAVED_QUERY_NAME,
        K::SAVED_QUERY_ARGUMENT,
        K::ARGUMENT_NAME,
        K::QUERY_PARAMETER,
        K::PARAMETER_DEFAULT,
        K::PARAMETER_NAME,
        K::REGEX,
        K::REGEX_PATTERN,
        K::REGEX_FLAGS,
        K::FUNCTION_CALL,
        K::FUNCTION_NAME,
        K::ARGUMENT_LIST,
        K::ARGUMENT,
        K::NAMED_ARGUMENT,
        K::ATTRIBUTED_EXPRESSION,
        K::EXPRESSION_ATTRIBUTE,
        K::IDENTIFIER,
        K::BINARY_EXPRESSION,
        K::UNARY_EXPRESSION,
        K::PARENTHESIZED_EXPRESSION,
        K::SUBQUERY,
        K::NAMED_SUBQUERY,
        K::ARRAY,
    ]
};

/// The `snake_case` name of `kind` (`FIELD_FILTER` is `field_filter`): tree-sitter's
/// name of the same production.
pub fn snake_case(kind: SyntaxKind) -> String {
    format!("{kind:?}").to_ascii_lowercase()
}

/// The rowan language of CQL.
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

/// A node of the CQL tree.
pub type SyntaxNode = rowan::SyntaxNode<Lang>;
/// A token of the CQL tree.
pub type SyntaxToken = rowan::SyntaxToken<Lang>;

/// The kind of each token of `cql.ungram`.
#[macro_export]
macro_rules! T {
    [and] => { $crate::SyntaxKind::AND_KW };
    [or] => { $crate::SyntaxKind::OR_KW };
    [not] => { $crate::SyntaxKind::NOT_KW };
    [case] => { $crate::SyntaxKind::CASE_KW };
    [match] => { $crate::SyntaxKind::MATCH_KW };
    [like] => { $crate::SyntaxKind::LIKE_KW };
    [true] => { $crate::SyntaxKind::TRUE_KW };
    [false] => { $crate::SyntaxKind::FALSE_KW };
    [word] => { $crate::SyntaxKind::WORD };
    [pattern] => { $crate::SyntaxKind::PATTERN };
    [number] => { $crate::SyntaxKind::NUMBER_TOKEN };
    [tag] => { $crate::SyntaxKind::TAG_TOKEN };
    [string] => { $crate::SyntaxKind::STRING_TOKEN };
    [function_name] => { $crate::SyntaxKind::FUNCTION_NAME_TOKEN };
    [saved_query_name] => { $crate::SyntaxKind::SAVED_QUERY_NAME_TOKEN };
    [parameter_name] => { $crate::SyntaxKind::PARAMETER_NAME_TOKEN };
    [regex_pattern] => { $crate::SyntaxKind::REGEX_PATTERN_TOKEN };
    [regex_flags] => { $crate::SyntaxKind::REGEX_FLAGS_TOKEN };
    [colon_eq] => { $crate::SyntaxKind::COLON_EQ };
    [eq_tilde] => { $crate::SyntaxKind::EQ_TILDE };
    [lt_eq_gt] => { $crate::SyntaxKind::LT_EQ_GT };
    [question_l_brace] => { $crate::SyntaxKind::QUESTION_L_BRACE };
    [|] => { $crate::SyntaxKind::PIPE };
    [=] => { $crate::SyntaxKind::EQ };
    [!=] => { $crate::SyntaxKind::NOT_EQ };
    [==] => { $crate::SyntaxKind::EQ_EQ };
    [<] => { $crate::SyntaxKind::LT };
    [<=] => { $crate::SyntaxKind::LT_EQ };
    [>] => { $crate::SyntaxKind::GT };
    [>=] => { $crate::SyntaxKind::GT_EQ };
    [<=>] => { $crate::SyntaxKind::LT_EQ_GT };
    [=>] => { $crate::SyntaxKind::FAT_ARROW };
    [!] => { $crate::SyntaxKind::BANG };
    [+] => { $crate::SyntaxKind::PLUS };
    [-] => { $crate::SyntaxKind::MINUS };
    [*] => { $crate::SyntaxKind::STAR };
    [/] => { $crate::SyntaxKind::SLASH };
    [%] => { $crate::SyntaxKind::PERCENT };
    ['('] => { $crate::SyntaxKind::L_PAREN };
    [')'] => { $crate::SyntaxKind::R_PAREN };
    ['['] => { $crate::SyntaxKind::L_BRACK };
    [']'] => { $crate::SyntaxKind::R_BRACK };
    ['{'] => { $crate::SyntaxKind::L_BRACE };
    ['}'] => { $crate::SyntaxKind::R_BRACE };
    [,] => { $crate::SyntaxKind::COMMA };
    [;] => { $crate::SyntaxKind::SEMI };
    [:] => { $crate::SyntaxKind::COLON };
    [$] => { $crate::SyntaxKind::DOLLAR };
    [?] => { $crate::SyntaxKind::QUESTION };
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
