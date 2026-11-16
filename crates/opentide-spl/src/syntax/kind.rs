//! The kinds of the SPL tree: token kinds first (every one below
//! [`TokenSet::CAPACITY`]), then node kinds, as `opentide-parse` asks of a
//! language. The node kinds are the tree-sitter grammar's node types; the
//! token kinds are its terminals, with the keywords the parser reads out of
//! words (`bump_as`) named here so the tree and the highlighter can tell
//! them apart.

use opentide_parse::TokenSet;

/// Declares [`SyntaxKind`] and [`ALL`], the table that turns a raw kind
/// back into a variant, from one list of names.
macro_rules! kinds {
    ($($(#[$doc:meta])* $name:ident,)*) => {
        /// A token or a node of the SPL tree.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u16)]
        #[expect(
            non_camel_case_types,
            reason = "the kinds are written as rust-analyzer's are"
        )]
        pub enum SyntaxKind {
            $($(#[$doc])* $name,)*
        }

        /// Every kind, in declaration order: `ALL[kind as usize] == kind`.
        const ALL: &[SyntaxKind] = &[$(SyntaxKind::$name,)*];
    };
}

kinds! {
    // ---- Tokens ----
    /// Spaces, tabs and line breaks (trivia).
    WHITESPACE,
    /// A comment between triple backticks (trivia).
    COMMENT,
    /// A character no token takes (an unclosed quote, a stray `!`).
    ERROR_TOKEN,
    /// End of input, what the parser sees past the last token.
    EOF,
    /// `|`
    PIPE,
    /// `[`
    L_BRACKET,
    /// `]`
    R_BRACKET,
    /// `(`
    L_PAREN,
    /// `)`
    R_PAREN,
    /// `,`
    COMMA,
    /// `=`
    EQ,
    /// `==`
    EQ2,
    /// `!=`
    NE,
    /// `<`
    LT,
    /// `>`
    GT,
    /// `<=`
    LE,
    /// `>=`
    GE,
    /// `<>`
    LT_GT,
    /// `=>`
    EQ_GT,
    /// `=<`
    EQ_LT,
    /// `!~`
    BANG_TILDE,
    /// `!`
    BANG,
    /// `+`
    PLUS,
    /// `-`
    MINUS,
    /// `*`
    STAR,
    /// `/`
    SLASH,
    /// `%`
    PERCENT,
    /// `.`
    DOT,
    /// A name: `[A-Za-z_][A-Za-z0-9_:]*(\.[A-Za-z0-9_:]+)*`.
    IDENT,
    /// `[0-9]+(\.[0-9]+)?`
    NUMBER_TOKEN,
    /// A field name that is not an `IDENT`: `a-b`, `{}.Id`, `@x`, `1h`.
    FIELD_WORD,
    /// The field tstats's `PREFIX(dst=)` makes, in `rename`: `dst=`.
    PREFIX_FIELD,
    /// A search wildcard: a run of word characters with a `*` in it.
    GLOB_TOKEN,
    /// Any other run of word characters: `-1h@h`, `10.0.0.0/8`.
    SEARCH_WORD_TOKEN,
    /// A search word spelled as a call with no arguments: `now()`.
    CALL_WORD,
    /// Eval's `{f}=v`: `a{f}b`.
    DYNAMIC_NAME,
    /// A `$token$` Splunk substitutes before the search runs.
    TOKEN_NAME,
    /// A `foreach` template: `<<FIELD>>`, `r<<MATCHSTR>>`.
    TEMPLATE_NAME,
    /// A string between `"` or `'`.
    STRING_TOKEN,
    /// A backtick macro, with its arguments.
    MACRO_TOKEN,
    /// The raw contents of `TERM(...)`, `CASE(...)` and `PREFIX(...)`.
    TERM_TEXT_TOKEN,
    /// `AND` (reserved in search)
    AND_KW,
    /// `OR` (reserved in search)
    OR_KW,
    /// `NOT` (reserved in search)
    NOT_KW,
    // Keywords the parser reads out of words, by position.
    /// `and`, in an expression
    AND_LOWER_KW,
    /// `or`, in an expression
    OR_LOWER_KW,
    /// `not`, in an expression
    NOT_LOWER_KW,
    /// `IN`
    IN_KW,
    /// `LIKE`
    LIKE_KW,
    /// `like`
    LIKE_LOWER_KW,
    /// `true`, `false`, `TRUE`, `FALSE`
    BOOL_KW,
    /// `TERM`
    TERM_KW,
    /// `CASE`
    CASE_KW,
    /// `PREFIX`
    PREFIX_KW,
    /// `as`
    AS_KW,
    /// `by`
    BY_KW,
    /// `over`
    OVER_KW,
    /// `output`
    OUTPUT_KW,
    /// `outputnew`
    OUTPUTNEW_KW,
    /// `desc`
    DESC_KW,
    /// `d`
    D_KW,
    /// `in` (chart `where`)
    IN_LOWER_KW,
    /// `notin`
    NOTIN_KW,
    /// `from`
    FROM_KW,
    /// `where`
    WHERE_KW,
    /// `sortby`
    SORTBY_KW,
    /// `keepevents`
    KEEPEVENTS_KW,
    /// `keepempty`
    KEEPEMPTY_KW,
    /// `consecutive`
    CONSECUTIVE_KW,
    /// `delim`
    DELIM_KW,
    /// `field`
    FIELD_KW,
    /// `datamodel`
    DATAMODEL_KW,
    /// `summariesonly`
    SUMMARIESONLY_KW,
    /// `prestats`
    PRESTATS_KW,
    /// `allow_old_summaries`
    ALLOW_OLD_SUMMARIES_KW,
    /// `fillnull_value`
    FILLNULL_VALUE_KW,
    // The commands with a rule of their own.
    /// `search`
    SEARCH_KW,
    /// `eval`
    EVAL_KW,
    /// `stats`, `eventstats`, `streamstats`, `sistats`
    STATS_KW,
    /// `chart`, `timechart`, `sichart`, `sitimechart`
    CHART_KW,
    /// `geostats`
    GEOSTATS_KW,
    /// `rex`
    REX_KW,
    /// `table`
    TABLE_KW,
    /// `rename`
    RENAME_KW,
    /// `fields`
    FIELDS_KW,
    /// `dedup`
    DEDUP_KW,
    /// `sort`
    SORT_KW,
    /// `head`
    HEAD_KW,
    /// `tail`
    TAIL_KW,
    /// `join`
    JOIN_KW,
    /// `lookup`
    LOOKUP_KW,
    /// `makemv`
    MAKEMV_KW,
    /// `mvexpand`
    MVEXPAND_KW,
    /// `tstats`
    TSTATS_KW,
    /// `fillnull`
    FILLNULL_KW,
    /// `foreach`
    FOREACH_KW,
    /// `spath`
    SPATH_KW,
    /// `tojson`
    TOJSON_KW,
    /// `inputlookup`
    INPUTLOOKUP_KW,
    /// `outputlookup`
    OUTPUTLOOKUP_KW,
    /// The name of a command the catalog knows and the grammar has no rule
    /// for (`makeresults`, `bin`, `top`, ...).
    CATALOG_COMMAND_WORD,

    // ---- Nodes (the ones of `spl.ungram`) ----
    SOURCE_FILE,
    PIPELINE,
    BARE_SEARCH,
    SEARCH_COMMAND,
    SEARCH_EXPRESSION,
    SEARCH_BOOLEAN,
    SEARCH_GROUP,
    IN_CLAUSE,
    VALUE_LIST,
    TERM_CLAUSE,
    CASE_CLAUSE,
    PREFIX_CLAUSE,
    TERM_TEXT,
    FIELD_VALUE,
    FIELD_REF,
    FIELD_VALUE_RHS,
    SUBSEARCH,
    WHERE_COMMAND,
    EVAL_COMMAND,
    ASSIGNMENT,
    STATS_COMMAND,
    OVER_CLAUSE,
    CHART_WHERE,
    BY_CLAUSE,
    AGGREGATE_ITEM,
    FUNCTION_CALL,
    REX_COMMAND,
    TABLE_COMMAND,
    RENAME_COMMAND,
    RENAME_ITEM,
    FIELDS_COMMAND,
    DEDUP_COMMAND,
    DEDUP_OPTION,
    SORT_COMMAND,
    SORT_ITEM,
    HEAD_COMMAND,
    TAIL_COMMAND,
    JOIN_COMMAND,
    LOOKUP_COMMAND,
    LOOKUP_FIELD,
    LOOKUP_ALIAS,
    MAKEMV_COMMAND,
    MVEXPAND_COMMAND,
    TSTATS_COMMAND,
    TSTATS_OPTION,
    FILLNULL_COMMAND,
    FOREACH_COMMAND,
    SPATH_COMMAND,
    TOJSON_COMMAND,
    INPUTLOOKUP_COMMAND,
    OUTPUTLOOKUP_COMMAND,
    CATALOG_COMMAND,
    CATALOG_COMMAND_NAME,
    UNKNOWN_COMMAND,
    ARGUMENT_LIST,
    COMMAND_OPTION,
    COMPARISON,
    BIN_EXPR,
    UNARY_EXPR,
    PAREN_EXPR,
    IDENTIFIER,
    NUMBER,
    STR,
    BOOLEAN,
    GLOB,
    SEARCH_WORD,
    MACRO_CALL,
    /// Unexpected tokens, and what a guard of the toolkit cut off.
    ERROR,
}

/// The first node kind: every kind before it is a token.
pub const FIRST_NODE: SyntaxKind = SyntaxKind::SOURCE_FILE;

impl SyntaxKind {
    /// The raw rowan kind.
    pub const fn raw(self) -> rowan::SyntaxKind {
        rowan::SyntaxKind(self as u16)
    }

    /// Whether this is a keyword the parser reads out of a word (`by`,
    /// `stats`, a catalog command name, ...).
    pub const fn is_keyword(self) -> bool {
        let k = self as u16;
        k >= SyntaxKind::AND_KW as u16 && k <= SyntaxKind::CATALOG_COMMAND_WORD as u16
    }

    /// Whether this is a token kind (a lexeme or a keyword read out of one).
    pub const fn is_token(self) -> bool {
        (self as u16) < FIRST_NODE as u16
    }

    /// A set of token kinds, for expected and recovery sets. Fails to
    /// compile (in a `const`) for a node kind or more than 16 kinds.
    pub const fn set(kinds: &[SyntaxKind]) -> TokenSet {
        assert!(kinds.len() <= 16, "a set of more than 16 kinds: split it");
        let mut raw = [rowan::SyntaxKind(0); 16];
        let mut i = 0;
        while i < kinds.len() {
            assert!(kinds[i].is_token(), "a node kind in a token set");
            raw[i] = kinds[i].raw();
            i += 1;
        }
        TokenSet::new(raw.split_at(kinds.len()).0)
    }
}

/// The rowan language of SPL.
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

/// A node of the tree.
pub type SyntaxNode = rowan::SyntaxNode<Lang>;
/// A token of the tree.
pub type SyntaxToken = rowan::SyntaxToken<Lang>;
/// A node or a token.
pub type SyntaxElement = rowan::SyntaxElement<Lang>;

/// The kind of each token of `spl.ungram`: `T![where]`, `T!['(']`.
#[macro_export]
#[doc(hidden)]
macro_rules! T {
    [!] => { $crate::syntax::SyntaxKind::BANG };
    [!=] => { $crate::syntax::SyntaxKind::NE };
    [!~] => { $crate::syntax::SyntaxKind::BANG_TILDE };
    [%] => { $crate::syntax::SyntaxKind::PERCENT };
    [']'] => { $crate::syntax::SyntaxKind::R_BRACKET };
    ['('] => { $crate::syntax::SyntaxKind::L_PAREN };
    [')'] => { $crate::syntax::SyntaxKind::R_PAREN };
    ['['] => { $crate::syntax::SyntaxKind::L_BRACKET };
    [*] => { $crate::syntax::SyntaxKind::STAR };
    [+] => { $crate::syntax::SyntaxKind::PLUS };
    [,] => { $crate::syntax::SyntaxKind::COMMA };
    [-] => { $crate::syntax::SyntaxKind::MINUS };
    [.] => { $crate::syntax::SyntaxKind::DOT };
    [/] => { $crate::syntax::SyntaxKind::SLASH };
    [<] => { $crate::syntax::SyntaxKind::LT };
    [<=] => { $crate::syntax::SyntaxKind::LE };
    [<>] => { $crate::syntax::SyntaxKind::LT_GT };
    [=] => { $crate::syntax::SyntaxKind::EQ };
    [=<] => { $crate::syntax::SyntaxKind::EQ_LT };
    [==] => { $crate::syntax::SyntaxKind::EQ2 };
    [=>] => { $crate::syntax::SyntaxKind::EQ_GT };
    [>] => { $crate::syntax::SyntaxKind::GT };
    [>=] => { $crate::syntax::SyntaxKind::GE };
    [AND] => { $crate::syntax::SyntaxKind::AND_KW };
    [CASE] => { $crate::syntax::SyntaxKind::CASE_KW };
    [IN] => { $crate::syntax::SyntaxKind::IN_KW };
    [LIKE] => { $crate::syntax::SyntaxKind::LIKE_KW };
    [like] => { $crate::syntax::SyntaxKind::LIKE_LOWER_KW };
    [not] => { $crate::syntax::SyntaxKind::NOT_LOWER_KW };
    [NOT] => { $crate::syntax::SyntaxKind::NOT_KW };
    [OR] => { $crate::syntax::SyntaxKind::OR_KW };
    [PREFIX] => { $crate::syntax::SyntaxKind::PREFIX_KW };
    [TERM] => { $crate::syntax::SyntaxKind::TERM_KW };
    [allow_old_summaries] => { $crate::syntax::SyntaxKind::ALLOW_OLD_SUMMARIES_KW };
    [and] => { $crate::syntax::SyntaxKind::AND_LOWER_KW };
    [as] => { $crate::syntax::SyntaxKind::AS_KW };
    [bool] => { $crate::syntax::SyntaxKind::BOOL_KW };
    [by] => { $crate::syntax::SyntaxKind::BY_KW };
    [call_word] => { $crate::syntax::SyntaxKind::CALL_WORD };
    [catalog_command_word] => { $crate::syntax::SyntaxKind::CATALOG_COMMAND_WORD };
    [chart] => { $crate::syntax::SyntaxKind::CHART_KW };
    [consecutive] => { $crate::syntax::SyntaxKind::CONSECUTIVE_KW };
    [d] => { $crate::syntax::SyntaxKind::D_KW };
    [datamodel] => { $crate::syntax::SyntaxKind::DATAMODEL_KW };
    [dedup] => { $crate::syntax::SyntaxKind::DEDUP_KW };
    [delim] => { $crate::syntax::SyntaxKind::DELIM_KW };
    [desc] => { $crate::syntax::SyntaxKind::DESC_KW };
    [dynamic_name] => { $crate::syntax::SyntaxKind::DYNAMIC_NAME };
    [eval] => { $crate::syntax::SyntaxKind::EVAL_KW };
    [field] => { $crate::syntax::SyntaxKind::FIELD_KW };
    [field_word] => { $crate::syntax::SyntaxKind::FIELD_WORD };
    [fields] => { $crate::syntax::SyntaxKind::FIELDS_KW };
    [fillnull] => { $crate::syntax::SyntaxKind::FILLNULL_KW };
    [fillnull_value] => { $crate::syntax::SyntaxKind::FILLNULL_VALUE_KW };
    [foreach] => { $crate::syntax::SyntaxKind::FOREACH_KW };
    [from] => { $crate::syntax::SyntaxKind::FROM_KW };
    [geostats] => { $crate::syntax::SyntaxKind::GEOSTATS_KW };
    [glob] => { $crate::syntax::SyntaxKind::GLOB_TOKEN };
    [head] => { $crate::syntax::SyntaxKind::HEAD_KW };
    [ident] => { $crate::syntax::SyntaxKind::IDENT };
    [in] => { $crate::syntax::SyntaxKind::IN_LOWER_KW };
    [inputlookup] => { $crate::syntax::SyntaxKind::INPUTLOOKUP_KW };
    [join] => { $crate::syntax::SyntaxKind::JOIN_KW };
    [keepempty] => { $crate::syntax::SyntaxKind::KEEPEMPTY_KW };
    [keepevents] => { $crate::syntax::SyntaxKind::KEEPEVENTS_KW };
    [lookup] => { $crate::syntax::SyntaxKind::LOOKUP_KW };
    [macro] => { $crate::syntax::SyntaxKind::MACRO_TOKEN };
    [makemv] => { $crate::syntax::SyntaxKind::MAKEMV_KW };
    [mvexpand] => { $crate::syntax::SyntaxKind::MVEXPAND_KW };
    [notin] => { $crate::syntax::SyntaxKind::NOTIN_KW };
    [number] => { $crate::syntax::SyntaxKind::NUMBER_TOKEN };
    [or] => { $crate::syntax::SyntaxKind::OR_LOWER_KW };
    [output] => { $crate::syntax::SyntaxKind::OUTPUT_KW };
    [outputlookup] => { $crate::syntax::SyntaxKind::OUTPUTLOOKUP_KW };
    [outputnew] => { $crate::syntax::SyntaxKind::OUTPUTNEW_KW };
    [over] => { $crate::syntax::SyntaxKind::OVER_KW };
    [prefix_field] => { $crate::syntax::SyntaxKind::PREFIX_FIELD };
    [prestats] => { $crate::syntax::SyntaxKind::PRESTATS_KW };
    [rename] => { $crate::syntax::SyntaxKind::RENAME_KW };
    [rex] => { $crate::syntax::SyntaxKind::REX_KW };
    [search] => { $crate::syntax::SyntaxKind::SEARCH_KW };
    [search_word] => { $crate::syntax::SyntaxKind::SEARCH_WORD_TOKEN };
    [sort] => { $crate::syntax::SyntaxKind::SORT_KW };
    [sortby] => { $crate::syntax::SyntaxKind::SORTBY_KW };
    [spath] => { $crate::syntax::SyntaxKind::SPATH_KW };
    [stats] => { $crate::syntax::SyntaxKind::STATS_KW };
    [string] => { $crate::syntax::SyntaxKind::STRING_TOKEN };
    [summariesonly] => { $crate::syntax::SyntaxKind::SUMMARIESONLY_KW };
    [table] => { $crate::syntax::SyntaxKind::TABLE_KW };
    [tail] => { $crate::syntax::SyntaxKind::TAIL_KW };
    [template_name] => { $crate::syntax::SyntaxKind::TEMPLATE_NAME };
    [term_text] => { $crate::syntax::SyntaxKind::TERM_TEXT_TOKEN };
    [tojson] => { $crate::syntax::SyntaxKind::TOJSON_KW };
    [token_name] => { $crate::syntax::SyntaxKind::TOKEN_NAME };
    [tstats] => { $crate::syntax::SyntaxKind::TSTATS_KW };
    [where] => { $crate::syntax::SyntaxKind::WHERE_KW };
    [|] => { $crate::syntax::SyntaxKind::PIPE };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_indexed_by_kind() {
        for (i, kind) in ALL.iter().enumerate() {
            assert_eq!(*kind as usize, i);
        }
    }

    #[test]
    fn every_token_kind_fits_a_token_set() {
        assert!(
            FIRST_NODE as u16 <= TokenSet::CAPACITY,
            "{} token kinds, {} fit a TokenSet",
            FIRST_NODE as u16,
            TokenSet::CAPACITY
        );
        assert!(u16::try_from(ALL.len()).is_ok());
    }
}
