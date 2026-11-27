//! The kinds of a YARA-L tree, its rowan language and the words the lexer
//! reads as keywords (#1227, ADR 0012).
//!
//! Token kinds come first, then node kinds (`opentide-parse` asks for it).
//! The node kinds are the nodes of `yaral.ungram`, which is the spec of the
//! tree; `cargo xtask codegen` generates its typed AST from it, over the
//! `SyntaxKind`, `Lang` and `T!` of this module.

use opentide_parse::TokenSet;

macro_rules! kinds {
    (
        keywords: [$($text:literal => $kw:ident),* $(,)?],
        contextual: [$($ctext:literal => $ckw:ident),* $(,)?],
        tokens: [$($token:ident),* $(,)?],
        nodes: [$($node:ident),* $(,)?] $(,)?
    ) => {
        /// A token or node kind of the YARA-L tree, spelled as rust-analyzer
        /// spells them. The keywords come first, then the other tokens
        /// (`ERROR` is the first node kind).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u16)]
        #[expect(
            non_camel_case_types,
            reason = "the kinds are the grammar's names, as rust-analyzer spells them"
        )]
        pub enum SyntaxKind {
            $($kw,)* $($ckw,)* $($token,)* $($node,)*
        }

        /// Every kind, in declaration order: `kind_from_raw` indexes it.
        const ALL: &[SyntaxKind] = &[
            $(SyntaxKind::$kw,)* $(SyntaxKind::$ckw,)* $(SyntaxKind::$token,)* $(SyntaxKind::$node,)*
        ];

        /// The reserved words: lower-case text and kind. Never a name, except
        /// where a name is read whatever its spelling (a rule name, a meta
        /// key, a path segment).
        pub const KEYWORDS: &[(&str, SyntaxKind)] = &[$(($text, SyntaxKind::$kw)),*];

        /// The words that are keywords only where the grammar takes them: the
        /// lexer reads them as [`SyntaxKind::IDENT`] and the parser re-kinds
        /// the ones it expects.
        pub const CONTEXTUAL: &[(&str, SyntaxKind)] = &[$(($ctext, SyntaxKind::$ckw)),*];
    };
}

kinds! {
    keywords: [
        "rule" => RULE_KW, "meta" => META_KW, "setup" => SETUP_KW, "events" => EVENTS_KW,
        "match" => MATCH_KW, "outcome" => OUTCOME_KW, "condition" => CONDITION_KW,
        "options" => OPTIONS_KW, "export" => EXPORT_KW, "dedup" => DEDUP_KW, "order" => ORDER_KW,
        "limit" => LIMIT_KW, "select" => SELECT_KW, "unselect" => UNSELECT_KW, "stage" => STAGE_KW,
        "and" => AND_KW, "or" => OR_KW, "not" => NOT_KW, "nocase" => NOCASE_KW, "in" => IN_KW,
        "regex" => REGEX_KW, "cidr" => CIDR_KW, "any" => ANY_KW, "all" => ALL_KW,
        "over" => OVER_KW, "by" => BY_KW, "before" => BEFORE_KW, "after" => AFTER_KW,
        "if" => IF_KW, "of" => OF_KW, "true" => TRUE_KW, "false" => FALSE_KW, "asc" => ASC_KW,
        "desc" => DESC_KW, "window_start" => WINDOW_START_KW, "window_end" => WINDOW_END_KW,
    ],
    contextual: [
        "every" => EVERY_KW, "first" => FIRST_KW, "cross" => CROSS_KW, "join" => JOIN_KW,
        "graph_override" => GRAPH_OVERRIDE_KW, "graph_append" => GRAPH_APPEND_KW,
        "graph_exclude" => GRAPH_EXCLUDE_KW,
    ],
    tokens: [
        // Trivia.
        WHITESPACE, COMMENT,
        // A character no token takes (an unclosed string, a lone `$`); the end of the input.
        ERROR_TOKEN, EOF,
        // Classes of tokens. A word after an access dot is a FIELD_NAME, whatever it is
        // spelled like; a keyword where a name is read is re-kinded IDENT by the parser.
        IDENT, FIELD_NAME, VAR_TOKEN, COUNT_TOKEN, REF_LIST_TOKEN, STRING, RAW_STRING, REGEX_LIT,
        INTEGER, FLOAT, DURATION,
        // Punctuation. ACCESS_DOT and INDEX_L_BRACK have no blank before them and follow a
        // variable, a name or `]`; DOT is the dot of `%table.column`.
        L_BRACE, R_BRACE, L_PAREN, R_PAREN, L_BRACK, INDEX_L_BRACK, R_BRACK, COMMA, COLON, DOT,
        ACCESS_DOT, EQ, NOT_EQ, LT, LT_EQ, GT, GT_EQ, PLUS, MINUS, STAR, SLASH, PERCENT, BANG,
    ],
    nodes: [
        // A run of tokens the grammar did not expect.
        ERROR,
        SOURCE_FILE, RULE_DECLARATION, RULE_NAME, META_SECTION, META_ENTRY, META_KEY,
        OPTIONS_SECTION, OPTION_ENTRY, OPTION_KEY, SETUP_SECTION, GRAPH_JOIN, GRAPH_APPEND, EVENTS_SECTION,
        OUTCOME_SECTION, CONDITION_SECTION, EXPORT_SECTION, MATCH_SECTION, MATCH_CLAUSE,
        MATCH_WINDOW, TIME_UNIT, DEDUP_SECTION, ORDER_SECTION, ORDER_ITEM, LIMIT_SECTION,
        SELECT_SECTION, UNSELECT_SECTION, SEARCH_QUERY, SEARCH_EVENTS, STAGE, STAGE_NAME,
        CROSS_JOIN, OR_EXPR, AND_EXPR, NOT_EXPR, COMPARISON, IN_EXPR, BINARY_EXPR, UNARY_EXPR,
        OF_EXPR, PAREN_EXPR, QUANTIFIED_FIELD, UDM_FIELD, BARE_FIELD, MEMBER, INDEX,
        FUNCTION_CALL, FUNCTION_NAME, ARGUMENTS, NAMED_ARGUMENT, ARGUMENT_NAME, TABLE_CALL, DATA_TABLE_COLUMN,
        IF_EXPR, ARRAY_EXPR, VARIABLE, COUNT_REF, REFERENCE_LIST, NAME_REF, WINDOW_BOUND, LITERAL,
    ],
}

use SyntaxKind as K;

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
    #[cfg(test)]
    pub const fn is_token(self) -> bool {
        (self as u16) < K::ERROR as u16
    }

    /// Whether this is a reserved word.
    pub const fn is_keyword(self) -> bool {
        (self as u16) <= K::WINDOW_END_KW as u16
    }

    /// Whether the lexer read this as a word: a name or a reserved word.
    pub const fn is_word(self) -> bool {
        matches!(self, K::IDENT) || self.is_keyword()
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

    /// The reserved word spelled `word` in any case.
    #[cfg(test)]
    pub fn from_keyword(word: &str) -> Option<Self> {
        KEYWORDS
            .iter()
            .find(|(text, _)| word.eq_ignore_ascii_case(text))
            .map(|&(_, kind)| kind)
    }

    /// The contextual keyword spelled `word` in any case.
    #[cfg(test)]
    pub fn from_contextual(word: &str) -> Option<Self> {
        CONTEXTUAL
            .iter()
            .find(|(text, _)| word.eq_ignore_ascii_case(text))
            .map(|&(_, kind)| kind)
    }

    /// How an error message spells the token the parser expected: its text,
    /// or what it stands for.
    pub fn describe(self) -> String {
        let text = match self {
            K::IDENT => return "a name".into(),
            K::FIELD_NAME => return "a field name".into(),
            K::VAR_TOKEN => return "a variable such as `$e`".into(),
            K::COUNT_TOKEN => return "a count such as `#e`".into(),
            K::REF_LIST_TOKEN => return "a reference list such as `%list`".into(),
            K::STRING | K::RAW_STRING => return "a string".into(),
            K::REGEX_LIT => return "a regular expression".into(),
            K::INTEGER => return "an integer".into(),
            K::FLOAT => return "a number".into(),
            K::DURATION => return "a duration such as `5m`".into(),
            K::EOF => return "end of input".into(),
            K::L_BRACE => "{",
            K::R_BRACE => "}",
            K::L_PAREN => "(",
            K::R_PAREN => ")",
            K::L_BRACK | K::INDEX_L_BRACK => "[",
            K::R_BRACK => "]",
            K::COMMA => ",",
            K::COLON => ":",
            K::DOT | K::ACCESS_DOT => ".",
            K::EQ => "=",
            K::NOT_EQ => "!=",
            K::LT => "<",
            K::LT_EQ => "<=",
            K::GT => ">",
            K::GT_EQ => ">=",
            K::PLUS => "+",
            K::MINUS => "-",
            K::STAR => "*",
            K::SLASH => "/",
            K::PERCENT => "%",
            K::BANG => "!",
            _ => {
                return KEYWORDS
                    .iter()
                    .chain(CONTEXTUAL)
                    .find(|(_, kind)| *kind == self)
                    .map_or_else(|| format!("{self:?}"), |(text, _)| format!("`{text}`"));
            }
        };
        format!("`{text}`")
    }
}

/// The rowan language of YARA-L.
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

/// A node of the YARA-L tree.
pub type SyntaxNode = rowan::SyntaxNode<Lang>;
/// A token of the YARA-L tree.
pub type SyntaxToken = rowan::SyntaxToken<Lang>;

/// The kind of each token of `yaral.ungram` (the typed AST's `T!`).
#[macro_export]
macro_rules! T {
    ['{'] => { $crate::syntax::SyntaxKind::L_BRACE };
    ['}'] => { $crate::syntax::SyntaxKind::R_BRACE };
    ['('] => { $crate::syntax::SyntaxKind::L_PAREN };
    [')'] => { $crate::syntax::SyntaxKind::R_PAREN };
    ['['] => { $crate::syntax::SyntaxKind::L_BRACK };
    [index_bracket] => { $crate::syntax::SyntaxKind::INDEX_L_BRACK };
    [']'] => { $crate::syntax::SyntaxKind::R_BRACK };
    [,] => { $crate::syntax::SyntaxKind::COMMA };
    [:] => { $crate::syntax::SyntaxKind::COLON };
    [table_dot] => { $crate::syntax::SyntaxKind::DOT };
    [.] => { $crate::syntax::SyntaxKind::ACCESS_DOT };
    [=] => { $crate::syntax::SyntaxKind::EQ };
    [!=] => { $crate::syntax::SyntaxKind::NOT_EQ };
    [<] => { $crate::syntax::SyntaxKind::LT };
    [<=] => { $crate::syntax::SyntaxKind::LT_EQ };
    [>] => { $crate::syntax::SyntaxKind::GT };
    [>=] => { $crate::syntax::SyntaxKind::GT_EQ };
    [+] => { $crate::syntax::SyntaxKind::PLUS };
    [-] => { $crate::syntax::SyntaxKind::MINUS };
    [*] => { $crate::syntax::SyntaxKind::STAR };
    [/] => { $crate::syntax::SyntaxKind::SLASH };
    [%] => { $crate::syntax::SyntaxKind::PERCENT };
    [!] => { $crate::syntax::SyntaxKind::BANG };
    [ident] => { $crate::syntax::SyntaxKind::IDENT };
    [field_name] => { $crate::syntax::SyntaxKind::FIELD_NAME };
    [variable] => { $crate::syntax::SyntaxKind::VAR_TOKEN };
    [count_ref] => { $crate::syntax::SyntaxKind::COUNT_TOKEN };
    [reference_list] => { $crate::syntax::SyntaxKind::REF_LIST_TOKEN };
    [string] => { $crate::syntax::SyntaxKind::STRING };
    [raw_string] => { $crate::syntax::SyntaxKind::RAW_STRING };
    [regex_lit] => { $crate::syntax::SyntaxKind::REGEX_LIT };
    [integer] => { $crate::syntax::SyntaxKind::INTEGER };
    [float] => { $crate::syntax::SyntaxKind::FLOAT };
    [duration] => { $crate::syntax::SyntaxKind::DURATION };
    [rule] => { $crate::syntax::SyntaxKind::RULE_KW };
    [meta] => { $crate::syntax::SyntaxKind::META_KW };
    [setup] => { $crate::syntax::SyntaxKind::SETUP_KW };
    [events] => { $crate::syntax::SyntaxKind::EVENTS_KW };
    [match] => { $crate::syntax::SyntaxKind::MATCH_KW };
    [outcome] => { $crate::syntax::SyntaxKind::OUTCOME_KW };
    [condition] => { $crate::syntax::SyntaxKind::CONDITION_KW };
    [options] => { $crate::syntax::SyntaxKind::OPTIONS_KW };
    [export] => { $crate::syntax::SyntaxKind::EXPORT_KW };
    [dedup] => { $crate::syntax::SyntaxKind::DEDUP_KW };
    [order] => { $crate::syntax::SyntaxKind::ORDER_KW };
    [limit] => { $crate::syntax::SyntaxKind::LIMIT_KW };
    [select] => { $crate::syntax::SyntaxKind::SELECT_KW };
    [unselect] => { $crate::syntax::SyntaxKind::UNSELECT_KW };
    [stage] => { $crate::syntax::SyntaxKind::STAGE_KW };
    [and] => { $crate::syntax::SyntaxKind::AND_KW };
    [or] => { $crate::syntax::SyntaxKind::OR_KW };
    [not] => { $crate::syntax::SyntaxKind::NOT_KW };
    [nocase] => { $crate::syntax::SyntaxKind::NOCASE_KW };
    [in] => { $crate::syntax::SyntaxKind::IN_KW };
    [regex] => { $crate::syntax::SyntaxKind::REGEX_KW };
    [cidr] => { $crate::syntax::SyntaxKind::CIDR_KW };
    [any] => { $crate::syntax::SyntaxKind::ANY_KW };
    [all] => { $crate::syntax::SyntaxKind::ALL_KW };
    [over] => { $crate::syntax::SyntaxKind::OVER_KW };
    [by] => { $crate::syntax::SyntaxKind::BY_KW };
    [before] => { $crate::syntax::SyntaxKind::BEFORE_KW };
    [after] => { $crate::syntax::SyntaxKind::AFTER_KW };
    [if] => { $crate::syntax::SyntaxKind::IF_KW };
    [of] => { $crate::syntax::SyntaxKind::OF_KW };
    [true] => { $crate::syntax::SyntaxKind::TRUE_KW };
    [false] => { $crate::syntax::SyntaxKind::FALSE_KW };
    [asc] => { $crate::syntax::SyntaxKind::ASC_KW };
    [desc] => { $crate::syntax::SyntaxKind::DESC_KW };
    [window_start] => { $crate::syntax::SyntaxKind::WINDOW_START_KW };
    [window_end] => { $crate::syntax::SyntaxKind::WINDOW_END_KW };
    [every] => { $crate::syntax::SyntaxKind::EVERY_KW };
    [first] => { $crate::syntax::SyntaxKind::FIRST_KW };
    [cross] => { $crate::syntax::SyntaxKind::CROSS_KW };
    [join] => { $crate::syntax::SyntaxKind::JOIN_KW };
    [graph_override] => { $crate::syntax::SyntaxKind::GRAPH_OVERRIDE_KW };
    [graph_append] => { $crate::syntax::SyntaxKind::GRAPH_APPEND_KW };
    [graph_exclude] => { $crate::syntax::SyntaxKind::GRAPH_EXCLUDE_KW };
}

/// The `Debug` names of the node kinds, the error node left out (`debug_node_kinds`).
pub(crate) fn node_kinds() -> Vec<String> {
    ALL.iter()
        .filter(|k| **k >= SyntaxKind::SOURCE_FILE && **k != SyntaxKind::ERROR)
        .map(|k| format!("{k:?}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// `yaral.ungram` without its comments.
    fn ungram() -> String {
        let text = include_str!("yaral.ungram");
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
        assert_eq!(ALL.last().copied(), Some(K::LITERAL));
        assert!(K::BANG.is_token() && !K::ERROR.is_token());
        assert!(K::WINDOW_END_KW.is_keyword() && !K::EVERY_KW.is_keyword());
        // A `TokenSet` panics on a kind past its capacity; the tokens are below `ERROR`.
        assert!((K::ERROR as usize) <= usize::from(TokenSet::CAPACITY));
        assert_eq!(
            <Lang as rowan::Language>::kind_from_raw(K::LITERAL.raw()),
            K::LITERAL
        );
    }

    #[test]
    fn a_word_is_one_text_one_kind() {
        let mut seen = BTreeSet::new();
        for (text, kind) in KEYWORDS.iter().chain(CONTEXTUAL) {
            assert!(seen.insert(*text), "`{text}` is in the tables twice");
            assert_eq!(kind.describe(), format!("`{text}`"));
            assert_eq!(
                SyntaxKind::from_keyword(&text.to_uppercase())
                    .or(SyntaxKind::from_contextual(text)),
                Some(*kind)
            );
        }
        assert_eq!(K::from_keyword("aNd"), Some(K::AND_KW));
        assert_eq!(K::from_keyword("metadata"), None);
        assert_eq!(K::from_keyword("every"), None, "contextual words are names");
        assert_eq!(K::from_contextual("Every"), Some(K::EVERY_KW));
    }

    /// The nodes of `yaral.ungram` (a rule that is not a choice of nodes) are
    /// exactly the node kinds.
    #[test]
    fn the_node_kinds_are_the_nodes_of_the_ungram() {
        let text = ungram();
        let mut rules: Vec<(String, String)> = Vec::new();
        for line in text.lines() {
            if let Some((name, rest)) = line.split_once(" =").filter(|(n, _)| {
                n.chars().next().is_some_and(char::is_uppercase)
                    && n.chars().all(|c| c.is_ascii_alphanumeric())
            }) {
                rules.push((name.to_owned(), rest.to_owned()));
            } else if let Some(last) = rules.last_mut() {
                last.1.push_str(line);
            }
        }
        let mut nodes = BTreeSet::new();
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

    /// Every token of `yaral.ungram` is a keyword, a punctuation or a class,
    /// and has its `T!`.
    #[test]
    fn the_tokens_of_the_ungram_have_their_t_macro() {
        let text = ungram();
        let macro_source = include_str!("syntax.rs");
        let mut rest = text.as_str();
        let mut tokens = BTreeSet::new();
        while let Some(open) = rest.find('\'') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('\'') else { break };
            tokens.insert(after[..close].to_owned());
            rest = &after[close + 1..];
        }
        assert!(tokens.len() > 60, "{} tokens", tokens.len());
        for token in &tokens {
            let quoted = format!("    ['{token}'] =>");
            let bare = format!("    [{token}] =>");
            assert!(
                macro_source.contains(&bare) || macro_source.contains(&quoted),
                "T![{token}] is missing"
            );
        }
    }
}
