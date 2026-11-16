//! The kinds of an ES|QL tree and its rowan language: the tokens the lexer
//! and parser name, and one node per named production of `esql.ungram`.
//!
//! The lexer reads every word as [`SyntaxKind::WORD`]; the parser re-kinds the
//! ones its grammar expects as keywords ([`SyntaxKind::from_keyword`]), or as
//! an identifier, because ES|QL's keywords are contextual.

use opentide_parse::TokenSet;

macro_rules! kinds {
    (
        keywords: [$($text:literal => $kw:ident),* $(,)?],
        tokens: [$($token:ident),* $(,)?],
        nodes: [$($node:ident),* $(,)?] $(,)?
    ) => {
        /// A token or node kind. Tokens come first (below `TokenSet::CAPACITY`).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u16)]
        #[expect(non_camel_case_types, reason = "the kinds are written as rust-analyzer's are, and named by the ungram")]
        #[allow(clippy::upper_case_acronyms, reason = "fires where a test includes this file privately, not where the crate exports the kinds: an expect cannot hold in both")]
        pub enum SyntaxKind {
            $($kw,)* $($token,)* $($node,)*
        }

        /// Every kind, in declaration order.
        const ALL: &[SyntaxKind] = &[$(SyntaxKind::$kw,)* $(SyntaxKind::$token,)* $(SyntaxKind::$node,)*];

        impl SyntaxKind {
            /// The lower-case text of a keyword kind.
            pub const fn keyword_text(self) -> Option<&'static str> {
                match self {
                    $(Self::$kw => Some($text),)*
                    _ => None,
                }
            }
        }

        /// The keywords: lower-case text and kind.
        pub(crate) const KEYWORD_KINDS: &[(&str, SyntaxKind)] = &[$(($text, SyntaxKind::$kw)),*];
    };
}

kinds! {
    keywords: [
        "from" => FROM_KW, "ts" => TS_KW, "row" => ROW_KW, "show" => SHOW_KW, "info" => INFO_KW,
        "explain" => EXPLAIN_KW, "promql" => PROMQL_KW, "set" => SET_KW, "metadata" => METADATA_KW,
        "where" => WHERE_KW, "eval" => EVAL_KW, "keep" => KEEP_KW, "drop" => DROP_KW,
        "rename" => RENAME_KW, "as" => AS_KW, "sort" => SORT_KW, "asc" => ASC_KW, "desc" => DESC_KW,
        "nulls" => NULLS_KW, "first" => FIRST_KW, "last" => LAST_KW, "limit" => LIMIT_KW,
        "stats" => STATS_KW, "inline" => INLINE_KW, "inlinestats" => INLINESTATS_KW, "by" => BY_KW,
        "dissect" => DISSECT_KW, "grok" => GROK_KW, "enrich" => ENRICH_KW, "on" => ON_KW,
        "with" => WITH_KW, "mv_expand" => MV_EXPAND_KW, "lookup" => LOOKUP_KW, "left" => LEFT_KW,
        "right" => RIGHT_KW, "full" => FULL_KW, "join" => JOIN_KW, "change_point" => CHANGE_POINT_KW,
        "completion" => COMPLETION_KW, "rerank" => RERANK_KW, "sample" => SAMPLE_KW,
        "fork" => FORK_KW, "fuse" => FUSE_KW, "score" => SCORE_KW, "key" => KEY_KW,
        "group" => GROUP_KW, "uri_parts" => URI_PARTS_KW, "registered_domain" => REGISTERED_DOMAIN_KW,
        "user_agent" => USER_AGENT_KW, "ip_location" => IP_LOCATION_KW,
        "metrics_info" => METRICS_INFO_KW, "ts_info" => TS_INFO_KW, "ts_collapse" => TS_COLLAPSE_KW,
        "dedup" => DEDUP_KW, "mmr" => MMR_KW, "highlight" => HIGHLIGHT_KW,
        "dense_vector" => DENSE_VECTOR_KW, "fillnull" => FILLNULL_KW, "and" => AND_KW,
        "or" => OR_KW, "not" => NOT_KW, "in" => IN_KW, "is" => IS_KW, "like" => LIKE_KW,
        "rlike" => RLIKE_KW, "null" => NULL_KW, "true" => TRUE_KW, "false" => FALSE_KW,
    ],
    tokens: [
        // Trivia.
        WHITESPACE, COMMENT,
        // What the lexer reads where a word may be a keyword or a name: the parser re-kinds it.
        WORD,
        // Text the lexer reads by the mode it is in; each is the one token of its node.
        SOURCE_TEXT, POLICY_PART, PROMQL_WORD, UNKNOWN_WORD, COMMAND_WORD,
        // Tokens the parser makes of a WORD.
        IDENT, ID_PATTERN_TEXT,
        // Literals and parameters.
        QUOTED_IDENT, PARAM, NUMBER_LIT, STRING_LIT,
        // Punctuation.
        PIPE, COMMA, SEMI, DOT, COLON, COLON_COLON, EQ, EQ_EQ, NOT_EQ, LT, LT_EQ, GT, GT_EQ,
        PLUS, MINUS, STAR_TOKEN, SLASH, PERCENT, L_PAREN, R_PAREN, L_BRACK, R_BRACK, L_BRACE, R_BRACE,
        // A character no token takes; the end of the input; a node of tokens the grammar did not expect.
        ERROR_TOKEN, EOF, ERROR,
    ],
    nodes: [
        SOURCE_FILE, SET_COMMAND, QUERY, FROM_COMMAND, TS_COMMAND, INDEX_PATTERN, CLUSTER, SELECTOR,
        INDEX_NAME, SOURCE_SUBQUERY, METADATA, METADATA_FIELD, ROW_COMMAND, SHOW_COMMAND,
        EXPLAIN_COMMAND, PROMQL_COMMAND, PROMQL_TEXT, WHERE_COMMAND, EVAL_COMMAND, KEEP_COMMAND,
        DROP_COMMAND, RENAME_COMMAND, RENAME_CLAUSE, SORT_COMMAND, ORDER_EXPRESSION, LIMIT_COMMAND,
        STATS_COMMAND, INLINE_STATS_COMMAND, AGGREGATE_FIELD, FIELD_ASSIGNMENT_OR_EXPRESSION,
        DISSECT_COMMAND, COMMAND_OPTION, GROK_COMMAND, ENRICH_COMMAND, ENRICH_POLICY, ENRICH_MODE,
        POLICY_NAME, ENRICH_WITH_CLAUSE, MV_EXPAND_COMMAND, JOIN_COMMAND, JOIN_QUALIFIER,
        CHANGE_POINT_COMMAND, COMPLETION_COMMAND, NAMED_PARAMETERS, RERANK_COMMAND, SAMPLE_COMMAND,
        FORK_COMMAND, FORK_BRANCH, FUSE_COMMAND, URI_PARTS_COMMAND, REGISTERED_DOMAIN_COMMAND,
        USER_AGENT_COMMAND, IP_LOCATION_COMMAND, METRICS_INFO_COMMAND, TS_INFO_COMMAND,
        TS_COLLAPSE_COMMAND, DEDUP_COMMAND, MMR_COMMAND, HIGHLIGHT_COMMAND, DENSE_VECTOR_COMMAND,
        FILL_NULL_COMMAND, UNKNOWN_COMMAND, COMMAND_NAME, UNKNOWN_TEXT, NOT_EXPRESSION,
        AND_EXPRESSION, OR_EXPRESSION, IN_EXPRESSION, IN_TUPLE, IS_NULL_EXPRESSION, LIKE_EXPRESSION,
        MATCH_EXPRESSION, COMPARISON, UNARY_EXPRESSION, BINARY_EXPRESSION, PARENTHESIZED_EXPRESSION,
        INLINE_CAST, TYPE_NAME, FUNCTION_CALL, STAR, MAP_EXPRESSION, MAP_ENTRY, NULL,
        QUALIFIED_INTERVAL, TIME_UNIT, NUMBER, BOOLEAN, ARRAY, STRING, NAME_PATTERN, ID_PATTERN,
        QUOTED_IDENTIFIER, QUALIFIED_NAME, IDENTIFIER, PARAMETER,
    ],
}

impl SyntaxKind {
    /// The raw rowan kind.
    pub const fn raw(self) -> rowan::SyntaxKind {
        rowan::SyntaxKind(self as u16)
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

    /// The keyword spelled `word` in any case.
    pub fn from_keyword(word: &str) -> Option<Self> {
        KEYWORD_KINDS
            .iter()
            .find(|(text, _)| word.eq_ignore_ascii_case(text))
            .map(|&(_, kind)| kind)
    }
}

/// The rowan language of ES|QL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lang {}

impl rowan::Language for Lang {
    type Kind = SyntaxKind;
    fn kind_from_raw(raw: rowan::SyntaxKind) -> SyntaxKind {
        ALL.get(usize::from(raw.0))
            .copied()
            .unwrap_or(SyntaxKind::ERROR)
    }
    fn kind_to_raw(kind: SyntaxKind) -> rowan::SyntaxKind {
        kind.raw()
    }
}

/// A node of the ES|QL tree.
pub type SyntaxNode = rowan::SyntaxNode<Lang>;
/// A token of the ES|QL tree.
pub type SyntaxToken = rowan::SyntaxToken<Lang>;

/// The kind of each token of `esql.ungram`, for the typed AST.
#[macro_export]
macro_rules! T {
    [from] => { $crate::SyntaxKind::FROM_KW };
    [ts] => { $crate::SyntaxKind::TS_KW };
    [row] => { $crate::SyntaxKind::ROW_KW };
    [show] => { $crate::SyntaxKind::SHOW_KW };
    [info] => { $crate::SyntaxKind::INFO_KW };
    [explain] => { $crate::SyntaxKind::EXPLAIN_KW };
    [promql] => { $crate::SyntaxKind::PROMQL_KW };
    [set] => { $crate::SyntaxKind::SET_KW };
    [metadata] => { $crate::SyntaxKind::METADATA_KW };
    [where] => { $crate::SyntaxKind::WHERE_KW };
    [eval] => { $crate::SyntaxKind::EVAL_KW };
    [keep] => { $crate::SyntaxKind::KEEP_KW };
    [drop] => { $crate::SyntaxKind::DROP_KW };
    [rename] => { $crate::SyntaxKind::RENAME_KW };
    [as] => { $crate::SyntaxKind::AS_KW };
    [sort] => { $crate::SyntaxKind::SORT_KW };
    [asc] => { $crate::SyntaxKind::ASC_KW };
    [desc] => { $crate::SyntaxKind::DESC_KW };
    [nulls] => { $crate::SyntaxKind::NULLS_KW };
    [first] => { $crate::SyntaxKind::FIRST_KW };
    [last] => { $crate::SyntaxKind::LAST_KW };
    [limit] => { $crate::SyntaxKind::LIMIT_KW };
    [stats] => { $crate::SyntaxKind::STATS_KW };
    [inline] => { $crate::SyntaxKind::INLINE_KW };
    [inlinestats] => { $crate::SyntaxKind::INLINESTATS_KW };
    [by] => { $crate::SyntaxKind::BY_KW };
    [dissect] => { $crate::SyntaxKind::DISSECT_KW };
    [grok] => { $crate::SyntaxKind::GROK_KW };
    [enrich] => { $crate::SyntaxKind::ENRICH_KW };
    [on] => { $crate::SyntaxKind::ON_KW };
    [with] => { $crate::SyntaxKind::WITH_KW };
    [mv_expand] => { $crate::SyntaxKind::MV_EXPAND_KW };
    [lookup] => { $crate::SyntaxKind::LOOKUP_KW };
    [left] => { $crate::SyntaxKind::LEFT_KW };
    [right] => { $crate::SyntaxKind::RIGHT_KW };
    [full] => { $crate::SyntaxKind::FULL_KW };
    [join] => { $crate::SyntaxKind::JOIN_KW };
    [change_point] => { $crate::SyntaxKind::CHANGE_POINT_KW };
    [completion] => { $crate::SyntaxKind::COMPLETION_KW };
    [rerank] => { $crate::SyntaxKind::RERANK_KW };
    [sample] => { $crate::SyntaxKind::SAMPLE_KW };
    [fork] => { $crate::SyntaxKind::FORK_KW };
    [fuse] => { $crate::SyntaxKind::FUSE_KW };
    [score] => { $crate::SyntaxKind::SCORE_KW };
    [key] => { $crate::SyntaxKind::KEY_KW };
    [group] => { $crate::SyntaxKind::GROUP_KW };
    [uri_parts] => { $crate::SyntaxKind::URI_PARTS_KW };
    [registered_domain] => { $crate::SyntaxKind::REGISTERED_DOMAIN_KW };
    [user_agent] => { $crate::SyntaxKind::USER_AGENT_KW };
    [ip_location] => { $crate::SyntaxKind::IP_LOCATION_KW };
    [metrics_info] => { $crate::SyntaxKind::METRICS_INFO_KW };
    [ts_info] => { $crate::SyntaxKind::TS_INFO_KW };
    [ts_collapse] => { $crate::SyntaxKind::TS_COLLAPSE_KW };
    [dedup] => { $crate::SyntaxKind::DEDUP_KW };
    [mmr] => { $crate::SyntaxKind::MMR_KW };
    [highlight] => { $crate::SyntaxKind::HIGHLIGHT_KW };
    [dense_vector] => { $crate::SyntaxKind::DENSE_VECTOR_KW };
    [fillnull] => { $crate::SyntaxKind::FILLNULL_KW };
    [and] => { $crate::SyntaxKind::AND_KW };
    [or] => { $crate::SyntaxKind::OR_KW };
    [not] => { $crate::SyntaxKind::NOT_KW };
    [in] => { $crate::SyntaxKind::IN_KW };
    [is] => { $crate::SyntaxKind::IS_KW };
    [like] => { $crate::SyntaxKind::LIKE_KW };
    [rlike] => { $crate::SyntaxKind::RLIKE_KW };
    [null] => { $crate::SyntaxKind::NULL_KW };
    [true] => { $crate::SyntaxKind::TRUE_KW };
    [false] => { $crate::SyntaxKind::FALSE_KW };
    [ident] => { $crate::SyntaxKind::IDENT };
    [id_pattern] => { $crate::SyntaxKind::ID_PATTERN_TEXT };
    [quoted_ident] => { $crate::SyntaxKind::QUOTED_IDENT };
    [param] => { $crate::SyntaxKind::PARAM };
    [number_lit] => { $crate::SyntaxKind::NUMBER_LIT };
    [string_lit] => { $crate::SyntaxKind::STRING_LIT };
    [source_text] => { $crate::SyntaxKind::SOURCE_TEXT };
    [policy_part] => { $crate::SyntaxKind::POLICY_PART };
    [promql_word] => { $crate::SyntaxKind::PROMQL_WORD };
    [unknown_word] => { $crate::SyntaxKind::UNKNOWN_WORD };
    [command_word] => { $crate::SyntaxKind::COMMAND_WORD };
    [|] => { $crate::SyntaxKind::PIPE };
    [,] => { $crate::SyntaxKind::COMMA };
    [;] => { $crate::SyntaxKind::SEMI };
    [.] => { $crate::SyntaxKind::DOT };
    [:] => { $crate::SyntaxKind::COLON };
    [::] => { $crate::SyntaxKind::COLON_COLON };
    [=] => { $crate::SyntaxKind::EQ };
    [==] => { $crate::SyntaxKind::EQ_EQ };
    [!=] => { $crate::SyntaxKind::NOT_EQ };
    [<] => { $crate::SyntaxKind::LT };
    [<=] => { $crate::SyntaxKind::LT_EQ };
    [>] => { $crate::SyntaxKind::GT };
    [>=] => { $crate::SyntaxKind::GT_EQ };
    [+] => { $crate::SyntaxKind::PLUS };
    [-] => { $crate::SyntaxKind::MINUS };
    [*] => { $crate::SyntaxKind::STAR_TOKEN };
    [/] => { $crate::SyntaxKind::SLASH };
    [%] => { $crate::SyntaxKind::PERCENT };
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
    fn every_keyword_kind_is_a_word_the_table_colours() {
        let table =
            opentide_highlight::keywords(opentide_core::LanguageId::Esql).unwrap_or_default();
        for &(text, kind) in KEYWORD_KINDS {
            assert_eq!(SyntaxKind::from_keyword(&text.to_uppercase()), Some(kind));
            // Every keyword but the literals has a row in the generators' table.
            if !["null", "true", "false"].contains(&text) {
                assert!(
                    table
                        .iter()
                        .any(|&(token, capture)| token == text && capture.name() == "keyword"),
                    "{text}"
                );
            }
        }
        assert!(
            usize::from(SyntaxKind::ERROR.raw().0)
                < usize::from(opentide_parse::TokenSet::CAPACITY)
        );
        assert_eq!(
            <Lang as rowan::Language>::kind_from_raw(SyntaxKind::PARAMETER.raw()),
            SyntaxKind::PARAMETER
        );
    }
}
