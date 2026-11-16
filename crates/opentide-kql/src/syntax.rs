//! The kinds of the KQL tree, its rowan language and the words the lexer
//! reads as keywords (#1230, ADR 0012).
//!
//! Token kinds come first, then node kinds (`opentide-parse` asks for it).
//! The node kinds are the nodes of `kql.ungram`, which is the spec of the
//! tree; `cargo xtask codegen` generates its typed AST from it, over the
//! `SyntaxKind`, `Lang` and `T!` of this module.

use opentide_parse::TokenSet;
use std::collections::HashMap;
use std::sync::OnceLock;

/// A token or node kind of the KQL tree, spelled as rust-analyzer spells
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
#[expect(
    non_camel_case_types,
    reason = "the kinds are the grammar's names, as rust-analyzer spells them"
)]
pub enum SyntaxKind {
    // Trivia and the ends.
    WHITESPACE,
    COMMENT,
    /// A character no token takes (a lone `!`, an unclosed string).
    ERROR_TOKEN,
    EOF,
    // Classes of tokens.
    IDENT,
    QUOTED_IDENT,
    STRING,
    NUMBER,
    TIMESPAN,
    TYPED_LITERAL,
    HINT_NAME,
    BOOLEAN,
    NULL_KW,
    /// `==`, `!=`, `<>`, `<`, `>`, `<=`, `>=`, `=~`, `!~` and the word
    /// operators that take one value (`has`, `!contains`, `startswith_cs`).
    CMP_OP,
    /// `in~`, `!in`, `!in~`, `has_any`, `has_all`, `has_any_ipv4`, ...: the
    /// operators followed by a list.
    SET_OP,
    /// `between`, `!between`.
    BETWEEN_OP,
    // Punctuation.
    PIPE,
    L_PAREN,
    R_PAREN,
    L_BRACKET,
    R_BRACKET,
    L_BRACE,
    R_BRACE,
    COMMA,
    SEMICOLON,
    COLON,
    DOT,
    DOT_DOT,
    EQ,
    FAT_ARROW,
    PLUS,
    MINUS,
    STAR,
    SLASH,
    PERCENT,
    // Keywords: a word is one only where the grammar takes it, and a name
    // everywhere else.
    LET_KW,
    DYNAMIC_KW,
    SEARCH_KW,
    FIND_KW,
    IN_KW,
    WHERE_KW,
    MATERIALIZE_KW,
    TOSCALAR_KW,
    DATATABLE_KW,
    EXTERNALDATA_KW,
    EXTERNAL_DATA_KW,
    WITH_KW,
    RANGE_KW,
    FROM_KW,
    TO_KW,
    STEP_KW,
    KIND_KW,
    BAGEXPANSION_KW,
    WITH_ITEMINDEX_KW,
    FILTER_KW,
    PROJECT_KW,
    PROJECT_AWAY_KW,
    PROJECT_RENAME_KW,
    PROJECT_KEEP_KW,
    PROJECT_REORDER_KW,
    EXTEND_KW,
    SUMMARIZE_KW,
    BY_KW,
    JOIN_KW,
    ON_KW,
    UNION_KW,
    PARSE_KW,
    PARSE_WHERE_KW,
    PARSE_KV_KW,
    LOOKUP_KW,
    TAKE_KW,
    LIMIT_KW,
    TOP_KW,
    COUNT_KW,
    MV_EXPAND_KW,
    MVEXPAND_KW,
    MV_APPLY_KW,
    TYPEOF_KW,
    MAKE_SERIES_KW,
    DEFAULT_KW,
    EVALUATE_KW,
    SORT_KW,
    ORDER_KW,
    DISTINCT_KW,
    RENDER_KW,
    PRINT_KW,
    TOP_NESTED_KW,
    OF_KW,
    OTHERS_KW,
    SAMPLE_DISTINCT_KW,
    FORK_KW,
    FACET_KW,
    PARTITION_KW,
    SCAN_KW,
    DECLARE_KW,
    OPTIONAL_KW,
    OUTPUT_KW,
    ALL_KW,
    NONE_KW,
    LAST_KW,
    FIRST_KW,
    NULLS_KW,
    ASC_KW,
    DESC_KW,
    GRANNY_ASC_KW,
    GRANNY_DESC_KW,
    INVOKE_KW,
    SERIALIZE_KW,
    AS_KW,
    GETSCHEMA_KW,
    SAMPLE_KW,
    CONSUME_KW,
    REDUCE_KW,
    MAKE_GRAPH_KW,
    GRAPH_MATCH_KW,
    GRAPH_SHORTEST_PATHS_KW,
    GRAPH_TO_TABLE_KW,
    GRAPH_MARK_COMPONENTS_KW,
    TOP_HITTERS_KW,
    AND_KW,
    OR_KW,
    NOT_KW,
    MATCHES_KW,
    REGEX_KW,
    // Nodes (`kql.ungram`; a choice of nodes is not a node).
    ERROR,
    SOURCE_FILE,
    LET_STATEMENT,
    FUNCTION_DEFINITION,
    PARAMETER,
    TYPE,
    TABLE_TYPE,
    TABLE_COLUMN,
    QUERY,
    CONTROL_COMMAND,
    TABULAR_EXPRESSION,
    TABULAR_SOURCE,
    TABLE_REF,
    PAREN_TABULAR,
    SEARCH_SOURCE,
    MATERIALIZE_EXPRESSION,
    DATATABLE_EXPRESSION,
    DATATABLE_COLUMN,
    EXTERNALDATA_EXPRESSION,
    OPERATOR_OPTION,
    OPTION_VALUE,
    MV_OPTION,
    HINT_OPTION,
    SUBQUERY,
    WHERE_OPERATOR,
    FILTER_OPERATOR,
    PROJECT_OPERATOR,
    PROJECT_AWAY_OPERATOR,
    PROJECT_KEEP_OPERATOR,
    PROJECT_REORDER_OPERATOR,
    REORDER_ITEM,
    PROJECT_RENAME_OPERATOR,
    RENAME_ITEM,
    COLUMN_PATTERN,
    EXTEND_OPERATOR,
    SUMMARIZE_OPERATOR,
    ASSIGNMENT,
    TUPLE_ASSIGNMENT,
    NAME_TUPLE,
    JOIN_OPERATOR,
    LOOKUP_OPERATOR,
    UNION_OPERATOR,
    PARSE_OPERATOR,
    PARSE_WHERE_OPERATOR,
    PARSE_PIECE,
    PARSE_COLUMN,
    PARSE_KV_OPERATOR,
    TAKE_OPERATOR,
    LIMIT_OPERATOR,
    TOP_OPERATOR,
    COUNT_OPERATOR,
    SORT_OPERATOR,
    SORT_ITEM,
    MV_EXPAND_OPERATOR,
    MV_EXPAND_ITEM,
    MV_APPLY_OPERATOR,
    MAKE_SERIES_OPERATOR,
    SERIES_AGGREGATE,
    SERIES_DEFAULT,
    EVALUATE_OPERATOR,
    DISTINCT_OPERATOR,
    RENDER_OPERATOR,
    PRINT_OPERATOR,
    RANGE_OPERATOR,
    TOP_NESTED_OPERATOR,
    TOP_NESTED_CLAUSE,
    TOP_NESTED_OF,
    TOP_NESTED_OTHERS,
    TOP_NESTED_BY,
    SAMPLE_DISTINCT_OPERATOR,
    FORK_OPERATOR,
    FORK_BRANCH,
    FACET_OPERATOR,
    PARTITION_OPERATOR,
    SCAN_OPERATOR,
    SCAN_STEP,
    KEYWORD_OPERATOR,
    UNKNOWN_OPERATOR,
    OR_EXPR,
    AND_EXPR,
    NOT_EXPR,
    COMPARISON_EXPR,
    IN_EXPR,
    BETWEEN_EXPR,
    ADDITIVE_EXPR,
    MULTIPLICATIVE_EXPR,
    UNARY_EXPR,
    EXPRESSION_LIST,
    RANGE,
    MEMBER_EXPR,
    INDEX_EXPR,
    FUNCTION_CALL,
    NAMED_ARGUMENT,
    STAR_ARG,
    TOSCALAR_EXPR,
    PAREN_EXPR,
    NAME_REF,
    LITERAL,
    DYNAMIC_LITERAL,
    JSON_ARRAY,
    JSON_OBJECT,
    JSON_PROPERTY,
    JSON_SCALAR,
}

use SyntaxKind as K;

/// The kinds in declaration order: `kind_from_raw` indexes it.
#[rustfmt::skip]
pub(crate) const ALL: &[SyntaxKind] = &[
    K::WHITESPACE, K::COMMENT, K::ERROR_TOKEN, K::EOF, K::IDENT, K::QUOTED_IDENT, K::STRING,
    K::NUMBER, K::TIMESPAN, K::TYPED_LITERAL, K::HINT_NAME, K::BOOLEAN, K::NULL_KW, K::CMP_OP,
    K::SET_OP, K::BETWEEN_OP, K::PIPE, K::L_PAREN, K::R_PAREN, K::L_BRACKET, K::R_BRACKET,
    K::L_BRACE, K::R_BRACE, K::COMMA, K::SEMICOLON, K::COLON, K::DOT, K::DOT_DOT, K::EQ,
    K::FAT_ARROW, K::PLUS, K::MINUS, K::STAR, K::SLASH, K::PERCENT, K::LET_KW, K::DYNAMIC_KW,
    K::SEARCH_KW, K::FIND_KW, K::IN_KW, K::WHERE_KW, K::MATERIALIZE_KW, K::TOSCALAR_KW,
    K::DATATABLE_KW, K::EXTERNALDATA_KW, K::EXTERNAL_DATA_KW, K::WITH_KW, K::RANGE_KW, K::FROM_KW,
    K::TO_KW, K::STEP_KW, K::KIND_KW, K::BAGEXPANSION_KW, K::WITH_ITEMINDEX_KW, K::FILTER_KW,
    K::PROJECT_KW, K::PROJECT_AWAY_KW, K::PROJECT_RENAME_KW, K::PROJECT_KEEP_KW,
    K::PROJECT_REORDER_KW, K::EXTEND_KW, K::SUMMARIZE_KW, K::BY_KW, K::JOIN_KW, K::ON_KW,
    K::UNION_KW, K::PARSE_KW, K::PARSE_WHERE_KW, K::PARSE_KV_KW, K::LOOKUP_KW, K::TAKE_KW,
    K::LIMIT_KW, K::TOP_KW, K::COUNT_KW, K::MV_EXPAND_KW, K::MVEXPAND_KW, K::MV_APPLY_KW,
    K::TYPEOF_KW, K::MAKE_SERIES_KW, K::DEFAULT_KW, K::EVALUATE_KW, K::SORT_KW, K::ORDER_KW,
    K::DISTINCT_KW, K::RENDER_KW, K::PRINT_KW, K::TOP_NESTED_KW, K::OF_KW, K::OTHERS_KW,
    K::SAMPLE_DISTINCT_KW, K::FORK_KW, K::FACET_KW, K::PARTITION_KW, K::SCAN_KW, K::DECLARE_KW,
    K::OPTIONAL_KW, K::OUTPUT_KW, K::ALL_KW, K::NONE_KW, K::LAST_KW, K::FIRST_KW, K::NULLS_KW,
    K::ASC_KW, K::DESC_KW, K::GRANNY_ASC_KW, K::GRANNY_DESC_KW, K::INVOKE_KW, K::SERIALIZE_KW,
    K::AS_KW, K::GETSCHEMA_KW, K::SAMPLE_KW, K::CONSUME_KW, K::REDUCE_KW, K::MAKE_GRAPH_KW,
    K::GRAPH_MATCH_KW, K::GRAPH_SHORTEST_PATHS_KW, K::GRAPH_TO_TABLE_KW,
    K::GRAPH_MARK_COMPONENTS_KW, K::TOP_HITTERS_KW, K::AND_KW, K::OR_KW, K::NOT_KW, K::MATCHES_KW,
    K::REGEX_KW, K::ERROR, K::SOURCE_FILE, K::LET_STATEMENT, K::FUNCTION_DEFINITION, K::PARAMETER,
    K::TYPE, K::TABLE_TYPE, K::TABLE_COLUMN, K::QUERY, K::CONTROL_COMMAND, K::TABULAR_EXPRESSION,
    K::TABULAR_SOURCE,
    K::TABLE_REF, K::PAREN_TABULAR, K::SEARCH_SOURCE, K::MATERIALIZE_EXPRESSION,
    K::DATATABLE_EXPRESSION, K::DATATABLE_COLUMN, K::EXTERNALDATA_EXPRESSION, K::OPERATOR_OPTION,
    K::OPTION_VALUE, K::MV_OPTION, K::HINT_OPTION, K::SUBQUERY, K::WHERE_OPERATOR,
    K::FILTER_OPERATOR, K::PROJECT_OPERATOR, K::PROJECT_AWAY_OPERATOR, K::PROJECT_KEEP_OPERATOR,
    K::PROJECT_REORDER_OPERATOR, K::REORDER_ITEM, K::PROJECT_RENAME_OPERATOR, K::RENAME_ITEM,
    K::COLUMN_PATTERN, K::EXTEND_OPERATOR, K::SUMMARIZE_OPERATOR, K::ASSIGNMENT, K::TUPLE_ASSIGNMENT, K::NAME_TUPLE,
    K::JOIN_OPERATOR, K::LOOKUP_OPERATOR, K::UNION_OPERATOR, K::PARSE_OPERATOR,
    K::PARSE_WHERE_OPERATOR, K::PARSE_PIECE, K::PARSE_COLUMN, K::PARSE_KV_OPERATOR,
    K::TAKE_OPERATOR, K::LIMIT_OPERATOR, K::TOP_OPERATOR, K::COUNT_OPERATOR, K::SORT_OPERATOR,
    K::SORT_ITEM, K::MV_EXPAND_OPERATOR, K::MV_EXPAND_ITEM, K::MV_APPLY_OPERATOR,
    K::MAKE_SERIES_OPERATOR, K::SERIES_AGGREGATE, K::SERIES_DEFAULT, K::EVALUATE_OPERATOR, K::DISTINCT_OPERATOR,
    K::RENDER_OPERATOR, K::PRINT_OPERATOR, K::RANGE_OPERATOR, K::TOP_NESTED_OPERATOR,
    K::TOP_NESTED_CLAUSE, K::TOP_NESTED_OF, K::TOP_NESTED_OTHERS, K::TOP_NESTED_BY, K::SAMPLE_DISTINCT_OPERATOR, K::FORK_OPERATOR, K::FORK_BRANCH,
    K::FACET_OPERATOR, K::PARTITION_OPERATOR, K::SCAN_OPERATOR, K::SCAN_STEP, K::KEYWORD_OPERATOR,
    K::UNKNOWN_OPERATOR, K::OR_EXPR, K::AND_EXPR, K::NOT_EXPR, K::COMPARISON_EXPR, K::IN_EXPR,
    K::BETWEEN_EXPR, K::ADDITIVE_EXPR, K::MULTIPLICATIVE_EXPR, K::UNARY_EXPR, K::EXPRESSION_LIST,
    K::RANGE, K::MEMBER_EXPR, K::INDEX_EXPR, K::FUNCTION_CALL, K::NAMED_ARGUMENT, K::STAR_ARG,
    K::TOSCALAR_EXPR, K::PAREN_EXPR, K::NAME_REF, K::LITERAL, K::DYNAMIC_LITERAL, K::JSON_ARRAY,
    K::JSON_OBJECT, K::JSON_PROPERTY, K::JSON_SCALAR,
];

impl SyntaxKind {
    /// The raw rowan kind.
    pub const fn raw(self) -> rowan::SyntaxKind {
        rowan::SyntaxKind(self as u16)
    }

    /// The kind of a raw rowan kind; `ERROR` for one that is none.
    pub fn from_raw(raw: rowan::SyntaxKind) -> Self {
        ALL.get(usize::from(raw.0)).copied().unwrap_or(K::ERROR)
    }

    /// Whether this is a token kind: the kinds below `ERROR`.
    pub const fn is_token(self) -> bool {
        (self as u16) < K::ERROR as u16
    }

    /// Whether a word of this kind is a name where the grammar wants one:
    /// every keyword and word operator (the lexer cannot tell, as the
    /// grammar of a pipe is not the grammar of an expression).
    pub const fn is_word(self) -> bool {
        matches!(
            self,
            K::IDENT | K::BOOLEAN | K::NULL_KW | K::CMP_OP | K::SET_OP | K::BETWEEN_OP
        ) || (self as u16 >= K::LET_KW as u16 && self as u16 <= K::REGEX_KW as u16)
    }

    /// A set of kinds, for the parser's expected and recovery sets.
    pub const fn set(kinds: &[SyntaxKind]) -> TokenSet {
        let mut raw = [rowan::SyntaxKind(0); 32];
        let mut i = 0;
        while i < kinds.len() && i < raw.len() {
            raw[i] = kinds[i].raw();
            i += 1;
        }
        TokenSet::new(raw.split_at(i).0)
    }

    /// How an error message spells the token the parser expected: its text,
    /// or what it stands for.
    pub fn describe(self) -> String {
        match self {
            K::IDENT | K::QUOTED_IDENT => "a name".into(),
            K::STRING => "a string".into(),
            K::NUMBER => "a number".into(),
            K::TIMESPAN => "a timespan".into(),
            K::TYPED_LITERAL => "a typed literal".into(),
            K::HINT_NAME => "a hint such as `hint.strategy`".into(),
            K::BOOLEAN => "`true` or `false`".into(),
            K::CMP_OP => "a comparison operator".into(),
            K::SET_OP => "`in`, `has_any` or another set operator".into(),
            K::BETWEEN_OP => "`between`".into(),
            K::EOF => "end of input".into(),
            _ => TEXTS
                .iter()
                .find(|(_, kind)| *kind == self)
                .map_or_else(|| format!("{self:?}"), |(text, _)| format!("`{text}`")),
        }
    }
}

/// The text of the kinds that have one (punctuation, keywords) and the word
/// operators' kinds, as the lexer reads them: case-sensitive, as Kusto's
/// keywords are. A name that is in no row is an [`SyntaxKind::IDENT`].
#[rustfmt::skip]
pub(crate) const TEXTS: &[(&str, SyntaxKind)] = &[
    ("|", K::PIPE), ("(", K::L_PAREN), (")", K::R_PAREN), ("[", K::L_BRACKET), ("]", K::R_BRACKET),
    ("{", K::L_BRACE), ("}", K::R_BRACE), (",", K::COMMA), (";", K::SEMICOLON), (":", K::COLON),
    (".", K::DOT), ("..", K::DOT_DOT), ("=", K::EQ), ("=>", K::FAT_ARROW), ("+", K::PLUS),
    ("-", K::MINUS), ("*", K::STAR), ("/", K::SLASH), ("%", K::PERCENT),
    ("let", K::LET_KW), ("dynamic", K::DYNAMIC_KW), ("search", K::SEARCH_KW),
    ("find", K::FIND_KW), ("in", K::IN_KW), ("where", K::WHERE_KW),
    ("materialize", K::MATERIALIZE_KW), ("toscalar", K::TOSCALAR_KW),
    ("datatable", K::DATATABLE_KW), ("externaldata", K::EXTERNALDATA_KW),
    ("external_data", K::EXTERNAL_DATA_KW), ("with", K::WITH_KW), ("range", K::RANGE_KW),
    ("from", K::FROM_KW), ("to", K::TO_KW), ("step", K::STEP_KW), ("kind", K::KIND_KW),
    ("bagexpansion", K::BAGEXPANSION_KW), ("with_itemindex", K::WITH_ITEMINDEX_KW),
    ("filter", K::FILTER_KW), ("project", K::PROJECT_KW), ("project-away", K::PROJECT_AWAY_KW),
    ("project-rename", K::PROJECT_RENAME_KW), ("project-keep", K::PROJECT_KEEP_KW),
    ("project-reorder", K::PROJECT_REORDER_KW), ("extend", K::EXTEND_KW),
    ("summarize", K::SUMMARIZE_KW), ("by", K::BY_KW), ("join", K::JOIN_KW), ("on", K::ON_KW),
    ("union", K::UNION_KW), ("parse", K::PARSE_KW), ("parse-where", K::PARSE_WHERE_KW),
    ("parse-kv", K::PARSE_KV_KW), ("lookup", K::LOOKUP_KW), ("take", K::TAKE_KW),
    ("limit", K::LIMIT_KW), ("top", K::TOP_KW), ("count", K::COUNT_KW),
    ("mv-expand", K::MV_EXPAND_KW), ("mvexpand", K::MVEXPAND_KW), ("mv-apply", K::MV_APPLY_KW),
    ("typeof", K::TYPEOF_KW), ("make-series", K::MAKE_SERIES_KW), ("default", K::DEFAULT_KW),
    ("evaluate", K::EVALUATE_KW), ("sort", K::SORT_KW), ("order", K::ORDER_KW),
    ("distinct", K::DISTINCT_KW), ("render", K::RENDER_KW), ("print", K::PRINT_KW),
    ("top-nested", K::TOP_NESTED_KW), ("of", K::OF_KW), ("others", K::OTHERS_KW),
    ("sample-distinct", K::SAMPLE_DISTINCT_KW), ("fork", K::FORK_KW), ("facet", K::FACET_KW),
    ("partition", K::PARTITION_KW), ("scan", K::SCAN_KW), ("declare", K::DECLARE_KW),
    ("optional", K::OPTIONAL_KW), ("output", K::OUTPUT_KW), ("all", K::ALL_KW),
    ("none", K::NONE_KW), ("last", K::LAST_KW), ("first", K::FIRST_KW), ("nulls", K::NULLS_KW),
    ("asc", K::ASC_KW), ("desc", K::DESC_KW), ("granny-asc", K::GRANNY_ASC_KW),
    ("granny-desc", K::GRANNY_DESC_KW), ("invoke", K::INVOKE_KW), ("serialize", K::SERIALIZE_KW),
    ("as", K::AS_KW), ("getschema", K::GETSCHEMA_KW), ("sample", K::SAMPLE_KW),
    ("consume", K::CONSUME_KW), ("reduce", K::REDUCE_KW), ("make-graph", K::MAKE_GRAPH_KW),
    ("graph-match", K::GRAPH_MATCH_KW), ("graph-shortest-paths", K::GRAPH_SHORTEST_PATHS_KW),
    ("graph-to-table", K::GRAPH_TO_TABLE_KW), ("graph-mark-components", K::GRAPH_MARK_COMPONENTS_KW),
    ("top-hitters", K::TOP_HITTERS_KW), ("and", K::AND_KW), ("or", K::OR_KW), ("not", K::NOT_KW),
    ("matches", K::MATCHES_KW), ("regex", K::REGEX_KW), ("null", K::NULL_KW),
    ("true", K::BOOLEAN), ("false", K::BOOLEAN), ("True", K::BOOLEAN), ("False", K::BOOLEAN),
    ("TRUE", K::BOOLEAN), ("FALSE", K::BOOLEAN),
];

/// The word operators, which the grammar reads as one token: a comparison
/// of two values, a test against a list, a range test.
#[rustfmt::skip]
pub(crate) const OPERATOR_WORDS: &[(&str, SyntaxKind)] = &[
    ("has", K::CMP_OP), ("!has", K::CMP_OP), ("has_cs", K::CMP_OP), ("!has_cs", K::CMP_OP),
    ("contains", K::CMP_OP), ("!contains", K::CMP_OP), ("contains_cs", K::CMP_OP),
    ("!contains_cs", K::CMP_OP), ("containscs", K::CMP_OP), ("notcontains", K::CMP_OP),
    ("notcontainscs", K::CMP_OP), ("startswith", K::CMP_OP), ("!startswith", K::CMP_OP),
    ("startswith_cs", K::CMP_OP), ("!startswith_cs", K::CMP_OP), ("endswith", K::CMP_OP),
    ("!endswith", K::CMP_OP), ("endswith_cs", K::CMP_OP), ("!endswith_cs", K::CMP_OP),
    ("hasprefix", K::CMP_OP), ("!hasprefix", K::CMP_OP), ("hasprefix_cs", K::CMP_OP),
    ("!hasprefix_cs", K::CMP_OP), ("hassuffix", K::CMP_OP), ("!hassuffix", K::CMP_OP),
    ("hassuffix_cs", K::CMP_OP), ("!hassuffix_cs", K::CMP_OP), ("has_ipv4", K::CMP_OP),
    ("has_ipv4_prefix", K::CMP_OP), ("!in", K::SET_OP), ("in~", K::SET_OP), ("!in~", K::SET_OP),
    ("has_any", K::SET_OP), ("has_all", K::SET_OP), ("has_any_ipv4", K::SET_OP),
    ("has_any_ipv4_prefix", K::SET_OP), ("between", K::BETWEEN_OP), ("!between", K::BETWEEN_OP),
];

/// The kind of a word (or of a `!word`): its keyword or operator kind, else
/// `None` for a name.
pub(crate) fn word_kind(text: &str) -> Option<SyntaxKind> {
    static WORDS: OnceLock<HashMap<&'static str, SyntaxKind>> = OnceLock::new();
    WORDS
        .get_or_init(|| {
            TEXTS
                .iter()
                .chain(OPERATOR_WORDS)
                .filter(|(text, _)| text.starts_with(|c: char| c.is_ascii_alphabetic() || c == '!'))
                .copied()
                .collect()
        })
        .get(text)
        .copied()
}

/// The rowan language of KQL.
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

/// A node of the KQL tree.
pub type SyntaxNode = rowan::SyntaxNode<Lang>;
/// A token of the KQL tree.
pub type SyntaxToken = rowan::SyntaxToken<Lang>;

/// The kind of each token of `kql.ungram` (the typed AST's `T!`).
#[macro_export]
macro_rules! T {
    [%] => { $crate::syntax::SyntaxKind::PERCENT };
    ['('] => { $crate::syntax::SyntaxKind::L_PAREN };
    [')'] => { $crate::syntax::SyntaxKind::R_PAREN };
    [*] => { $crate::syntax::SyntaxKind::STAR };
    [+] => { $crate::syntax::SyntaxKind::PLUS };
    [,] => { $crate::syntax::SyntaxKind::COMMA };
    [-] => { $crate::syntax::SyntaxKind::MINUS };
    [.] => { $crate::syntax::SyntaxKind::DOT };
    [..] => { $crate::syntax::SyntaxKind::DOT_DOT };
    [/] => { $crate::syntax::SyntaxKind::SLASH };
    [:] => { $crate::syntax::SyntaxKind::COLON };
    [;] => { $crate::syntax::SyntaxKind::SEMICOLON };
    [=] => { $crate::syntax::SyntaxKind::EQ };
    [=>] => { $crate::syntax::SyntaxKind::FAT_ARROW };
    ['['] => { $crate::syntax::SyntaxKind::L_BRACKET };
    [']'] => { $crate::syntax::SyntaxKind::R_BRACKET };
    [all] => { $crate::syntax::SyntaxKind::ALL_KW };
    [and] => { $crate::syntax::SyntaxKind::AND_KW };
    [as] => { $crate::syntax::SyntaxKind::AS_KW };
    [asc] => { $crate::syntax::SyntaxKind::ASC_KW };
    [bagexpansion] => { $crate::syntax::SyntaxKind::BAGEXPANSION_KW };
    [between_op] => { $crate::syntax::SyntaxKind::BETWEEN_OP };
    [boolean] => { $crate::syntax::SyntaxKind::BOOLEAN };
    [by] => { $crate::syntax::SyntaxKind::BY_KW };
    [cmp_op] => { $crate::syntax::SyntaxKind::CMP_OP };
    [consume] => { $crate::syntax::SyntaxKind::CONSUME_KW };
    [count] => { $crate::syntax::SyntaxKind::COUNT_KW };
    [datatable] => { $crate::syntax::SyntaxKind::DATATABLE_KW };
    [declare] => { $crate::syntax::SyntaxKind::DECLARE_KW };
    [default] => { $crate::syntax::SyntaxKind::DEFAULT_KW };
    [desc] => { $crate::syntax::SyntaxKind::DESC_KW };
    [distinct] => { $crate::syntax::SyntaxKind::DISTINCT_KW };
    [dynamic] => { $crate::syntax::SyntaxKind::DYNAMIC_KW };
    [evaluate] => { $crate::syntax::SyntaxKind::EVALUATE_KW };
    [extend] => { $crate::syntax::SyntaxKind::EXTEND_KW };
    [external_data] => { $crate::syntax::SyntaxKind::EXTERNAL_DATA_KW };
    [externaldata] => { $crate::syntax::SyntaxKind::EXTERNALDATA_KW };
    [facet] => { $crate::syntax::SyntaxKind::FACET_KW };
    [filter] => { $crate::syntax::SyntaxKind::FILTER_KW };
    [find] => { $crate::syntax::SyntaxKind::FIND_KW };
    [first] => { $crate::syntax::SyntaxKind::FIRST_KW };
    [fork] => { $crate::syntax::SyntaxKind::FORK_KW };
    [from] => { $crate::syntax::SyntaxKind::FROM_KW };
    [getschema] => { $crate::syntax::SyntaxKind::GETSCHEMA_KW };
    [granny-asc] => { $crate::syntax::SyntaxKind::GRANNY_ASC_KW };
    [granny-desc] => { $crate::syntax::SyntaxKind::GRANNY_DESC_KW };
    [graph-mark-components] => { $crate::syntax::SyntaxKind::GRAPH_MARK_COMPONENTS_KW };
    [graph-match] => { $crate::syntax::SyntaxKind::GRAPH_MATCH_KW };
    [graph-shortest-paths] => { $crate::syntax::SyntaxKind::GRAPH_SHORTEST_PATHS_KW };
    [graph-to-table] => { $crate::syntax::SyntaxKind::GRAPH_TO_TABLE_KW };
    [hint_name] => { $crate::syntax::SyntaxKind::HINT_NAME };
    [ident] => { $crate::syntax::SyntaxKind::IDENT };
    [in] => { $crate::syntax::SyntaxKind::IN_KW };
    [invoke] => { $crate::syntax::SyntaxKind::INVOKE_KW };
    [join] => { $crate::syntax::SyntaxKind::JOIN_KW };
    [kind] => { $crate::syntax::SyntaxKind::KIND_KW };
    [last] => { $crate::syntax::SyntaxKind::LAST_KW };
    [let] => { $crate::syntax::SyntaxKind::LET_KW };
    [limit] => { $crate::syntax::SyntaxKind::LIMIT_KW };
    [lookup] => { $crate::syntax::SyntaxKind::LOOKUP_KW };
    [make-graph] => { $crate::syntax::SyntaxKind::MAKE_GRAPH_KW };
    [make-series] => { $crate::syntax::SyntaxKind::MAKE_SERIES_KW };
    [matches] => { $crate::syntax::SyntaxKind::MATCHES_KW };
    [materialize] => { $crate::syntax::SyntaxKind::MATERIALIZE_KW };
    [mv-apply] => { $crate::syntax::SyntaxKind::MV_APPLY_KW };
    [mv-expand] => { $crate::syntax::SyntaxKind::MV_EXPAND_KW };
    [mvexpand] => { $crate::syntax::SyntaxKind::MVEXPAND_KW };
    [none] => { $crate::syntax::SyntaxKind::NONE_KW };
    [not] => { $crate::syntax::SyntaxKind::NOT_KW };
    [null] => { $crate::syntax::SyntaxKind::NULL_KW };
    [nulls] => { $crate::syntax::SyntaxKind::NULLS_KW };
    [number] => { $crate::syntax::SyntaxKind::NUMBER };
    [of] => { $crate::syntax::SyntaxKind::OF_KW };
    [on] => { $crate::syntax::SyntaxKind::ON_KW };
    [optional] => { $crate::syntax::SyntaxKind::OPTIONAL_KW };
    [or] => { $crate::syntax::SyntaxKind::OR_KW };
    [order] => { $crate::syntax::SyntaxKind::ORDER_KW };
    [others] => { $crate::syntax::SyntaxKind::OTHERS_KW };
    [output] => { $crate::syntax::SyntaxKind::OUTPUT_KW };
    [parse] => { $crate::syntax::SyntaxKind::PARSE_KW };
    [parse-kv] => { $crate::syntax::SyntaxKind::PARSE_KV_KW };
    [parse-where] => { $crate::syntax::SyntaxKind::PARSE_WHERE_KW };
    [partition] => { $crate::syntax::SyntaxKind::PARTITION_KW };
    [print] => { $crate::syntax::SyntaxKind::PRINT_KW };
    [project] => { $crate::syntax::SyntaxKind::PROJECT_KW };
    [project-away] => { $crate::syntax::SyntaxKind::PROJECT_AWAY_KW };
    [project-keep] => { $crate::syntax::SyntaxKind::PROJECT_KEEP_KW };
    [project-rename] => { $crate::syntax::SyntaxKind::PROJECT_RENAME_KW };
    [project-reorder] => { $crate::syntax::SyntaxKind::PROJECT_REORDER_KW };
    [quoted_ident] => { $crate::syntax::SyntaxKind::QUOTED_IDENT };
    [range] => { $crate::syntax::SyntaxKind::RANGE_KW };
    [reduce] => { $crate::syntax::SyntaxKind::REDUCE_KW };
    [regex] => { $crate::syntax::SyntaxKind::REGEX_KW };
    [render] => { $crate::syntax::SyntaxKind::RENDER_KW };
    [sample] => { $crate::syntax::SyntaxKind::SAMPLE_KW };
    [sample-distinct] => { $crate::syntax::SyntaxKind::SAMPLE_DISTINCT_KW };
    [scan] => { $crate::syntax::SyntaxKind::SCAN_KW };
    [search] => { $crate::syntax::SyntaxKind::SEARCH_KW };
    [serialize] => { $crate::syntax::SyntaxKind::SERIALIZE_KW };
    [set_op] => { $crate::syntax::SyntaxKind::SET_OP };
    [sort] => { $crate::syntax::SyntaxKind::SORT_KW };
    [step] => { $crate::syntax::SyntaxKind::STEP_KW };
    [string] => { $crate::syntax::SyntaxKind::STRING };
    [summarize] => { $crate::syntax::SyntaxKind::SUMMARIZE_KW };
    [take] => { $crate::syntax::SyntaxKind::TAKE_KW };
    [timespan] => { $crate::syntax::SyntaxKind::TIMESPAN };
    [to] => { $crate::syntax::SyntaxKind::TO_KW };
    [top] => { $crate::syntax::SyntaxKind::TOP_KW };
    [top-hitters] => { $crate::syntax::SyntaxKind::TOP_HITTERS_KW };
    [top-nested] => { $crate::syntax::SyntaxKind::TOP_NESTED_KW };
    [toscalar] => { $crate::syntax::SyntaxKind::TOSCALAR_KW };
    [typed_literal] => { $crate::syntax::SyntaxKind::TYPED_LITERAL };
    [typeof] => { $crate::syntax::SyntaxKind::TYPEOF_KW };
    [union] => { $crate::syntax::SyntaxKind::UNION_KW };
    [where] => { $crate::syntax::SyntaxKind::WHERE_KW };
    [with] => { $crate::syntax::SyntaxKind::WITH_KW };
    [with_itemindex] => { $crate::syntax::SyntaxKind::WITH_ITEMINDEX_KW };
    ['{'] => { $crate::syntax::SyntaxKind::L_BRACE };
    [|] => { $crate::syntax::SyntaxKind::PIPE };
    ['}'] => { $crate::syntax::SyntaxKind::R_BRACE };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// `kql.ungram` without its comments.
    fn ungram() -> String {
        let text = include_str!("kql.ungram");
        text.lines()
            .map(|line| line.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_kind_table_is_in_declaration_order() {
        for (i, kind) in ALL.iter().enumerate() {
            assert_eq!(*kind as usize, i, "{kind:?} is out of place in ALL");
        }
        assert_eq!(
            ALL.last().copied(),
            Some(K::JSON_SCALAR),
            "a kind is missing from ALL"
        );
        assert_eq!(ALL.len(), K::JSON_SCALAR as usize + 1);
        assert!(!K::ERROR.is_token() && K::REGEX_KW.is_token());
        assert!((K::LET_KW as usize..=K::REGEX_KW as usize).all(|i| ALL[i].is_word()));
    }

    #[test]
    fn every_token_kind_fits_a_token_set() {
        // A `TokenSet` panics on a kind past its capacity; the tokens are below `ERROR`.
        assert!((K::ERROR as usize) <= usize::from(TokenSet::CAPACITY));
        let set = SyntaxKind::set(&[K::PIPE, K::REGEX_KW]);
        assert!(set.contains(K::REGEX_KW.raw()) && !set.contains(K::EQ.raw()));
    }

    #[test]
    fn a_word_is_one_text_one_kind() {
        let mut seen = BTreeSet::new();
        for (text, kind) in TEXTS.iter().chain(OPERATOR_WORDS) {
            assert!(seen.insert(*text), "`{text}` is in the tables twice");
            assert!(!kind.describe().is_empty(), "{text}");
        }
        assert_eq!(word_kind("where"), Some(K::WHERE_KW));
        assert_eq!(word_kind("Where"), None, "keywords are case-sensitive");
        assert_eq!(word_kind("!has"), Some(K::CMP_OP));
        assert_eq!(word_kind("True"), Some(K::BOOLEAN));
        assert_eq!(word_kind("tRuE"), None);
        assert_eq!(word_kind("|"), None);
    }

    #[test]
    fn describe_spells_what_the_parser_expected() {
        assert_eq!(K::WHERE_KW.describe(), "`where`");
        assert_eq!(K::PROJECT_AWAY_KW.describe(), "`project-away`");
        assert_eq!(K::PIPE.describe(), "`|`");
        assert_eq!(K::IDENT.describe(), "a name");
        assert_eq!(K::EOF.describe(), "end of input");
    }

    /// The nodes of `kql.ungram` (a rule that is not a choice of nodes) are
    /// exactly the node kinds.
    #[test]
    fn the_node_kinds_are_the_nodes_of_the_ungram() {
        let text = ungram();
        let mut nodes = BTreeSet::new();
        let mut rule_start = None;
        let mut rules = Vec::new();
        for line in text.lines() {
            if let Some((name, rest)) = line.split_once(" =").filter(|(n, _)| {
                n.chars().next().is_some_and(char::is_uppercase)
                    && n.chars().all(|c| c.is_ascii_alphanumeric())
            }) {
                rule_start = Some(rules.len());
                rules.push((name.to_owned(), rest.to_owned()));
            } else if let Some(i) = rule_start {
                rules[i].1.push_str(line);
            }
        }
        for (name, rule) in &rules {
            let choice = rule.contains('|')
                && rule.split('|').all(|alt| {
                    let alt = alt.trim();
                    !alt.is_empty() && alt.chars().all(|c| c.is_ascii_alphanumeric())
                })
                && rule.chars().any(char::is_uppercase);
            if !choice {
                nodes.insert(upper_snake(name));
            }
        }
        let kinds: BTreeSet<String> = ALL[K::ERROR as usize + 1..]
            .iter()
            .map(|k| format!("{k:?}"))
            .collect();
        assert_eq!(nodes, kinds);
    }

    fn upper_snake(name: &str) -> String {
        let mut out = String::new();
        for (i, c) in name.chars().enumerate() {
            if c.is_uppercase() && i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_uppercase());
        }
        out
    }

    /// Every token of `kql.ungram` is a class, a punctuation or a word the
    /// lexer reads, and has its `T!`.
    #[test]
    fn the_tokens_of_the_ungram_are_known() {
        let classes = [
            "ident",
            "quoted_ident",
            "string",
            "number",
            "timespan",
            "typed_literal",
            "hint_name",
            "boolean",
            "null",
            "cmp_op",
            "set_op",
            "between_op",
        ];
        let text = ungram();
        let mut tokens = BTreeSet::new();
        let mut rest = text.as_str();
        while let Some(open) = rest.find('\'') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('\'') else { break };
            tokens.insert(after[..close].to_owned());
            rest = &after[close + 1..];
        }
        let macro_source = include_str!("syntax.rs");
        for token in &tokens {
            let known =
                classes.contains(&token.as_str()) || TEXTS.iter().any(|(text, _)| text == token);
            assert!(known, "`{token}` of the ungram is not a token of the lexer");
            let quoted = format!("['{token}']");
            let bare = format!("    [{token}] =>");
            assert!(
                macro_source.contains(&bare) || macro_source.contains(&format!("    {quoted} =>")),
                "T![{token}] is missing"
            );
        }
    }
}
