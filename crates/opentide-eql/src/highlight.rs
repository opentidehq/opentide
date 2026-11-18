//! Highlighting from the rowan tree: each token's capture from its kind and the node it stands
//! in, by the patterns of the old `highlights.scm` in their order (the first that matches
//! wins), and the expression-depth pre-scan Elasticsearch runs over the same tokens.

use crate::lexical;
use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use opentide_core::ByteSpan;
use rowan::NodeOrToken;
use std::collections::HashMap;
use std::sync::OnceLock;

/// A node that stands for one token (`identifier`, `string`, `any`, ...): it is captured as a
/// whole, by its kind and its place in its parent. (`boolean` is not one: its `true` or `false`
/// is captured as a token.)
pub(crate) fn is_leaf(kind: K) -> bool {
    matches!(
        kind,
        K::ANY
            | K::MISSING_EVENT_OPEN
            | K::CASE_INSENSITIVE_NAME
            | K::OPTIONAL_MARKER
            | K::INDEX
            | K::IDENTIFIER
            | K::QUOTED_IDENTIFIER
            | K::NULL
            | K::NUMBER
            | K::STRING
    )
}

/// The name of a token outside a leaf node: its text for a keyword or punctuation, or what it
/// is when it stands in an error region (a name or a literal with no node of its own).
pub(crate) fn token_name(kind: K, text: &str) -> &'static str {
    match kind {
        K::IN_TILDE => "in~",
        K::LIKE_TILDE => "like~",
        K::REGEX_TILDE => "regex~",
        K::PIPE => "|",
        K::EQ => "=",
        K::EQ_EQ => "==",
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
        K::L_PAREN => "(",
        K::R_PAREN => ")",
        K::L_BRACK => "[",
        K::R_BRACK => "]",
        K::COMMA => ",",
        K::DOT => ".",
        K::COLON => ":",
        K::QUESTION => "?",
        K::BANG_L_BRACK => "![",
        // A keyword is lower case: its text is its name.
        _ if let Some(keyword) = crate::KEYWORD_WORDS.iter().find(|k| **k == text) => keyword,
        K::WORD => ERROR_WORD,
        K::TILDE_WORD => ERROR_TILDE_WORD,
        K::QUOTED_IDENT_TOKEN => ERROR_QUOTED,
        K::STRING_TOKEN => ERROR_STRING,
        K::NUMBER_TOKEN => ERROR_NUMBER,
        _ => "ERROR",
    }
}

/// Tokens in an error region, by what the lexer cut.
pub(crate) const ERROR_WORD: &str = "ERROR word";
pub(crate) const ERROR_TILDE_WORD: &str = "ERROR tilde_word";
pub(crate) const ERROR_QUOTED: &str = "ERROR quoted_identifier";
pub(crate) const ERROR_STRING: &str = "ERROR string";
pub(crate) const ERROR_NUMBER: &str = "ERROR number";

/// Each captured token of the tree, in document order, with its span and capture.
#[cfg(test)]
pub(crate) fn captures(root: &SyntaxNode) -> Vec<(ByteSpan, &'static str)> {
    visible_tokens(root)
        .filter_map(|t| capture_of(&t))
        .collect()
}

/// The span and capture of `token`, if it is visible and captured: what
/// [`captures`] gathers, for a walk that meets the tokens itself (ADR 0014
/// §5a).
pub(crate) fn capture_of(token: &SyntaxToken) -> Option<(ByteSpan, &'static str)> {
    if token.kind() == K::WHITESPACE || token.text().is_empty() {
        return None;
    }
    let parent = token.parent()?;
    let capture = if matches!(token.kind(), K::LINE_COMMENT | K::BLOCK_COMMENT) {
        Some("comment")
    } else if is_leaf(parent.kind()) {
        leaf_capture(&parent)
    } else {
        token_capture(token, parent.kind())
    };
    Some((span_of(token), capture?))
}

/// The tokens a reader sees: everything but whitespace, with a length.
fn visible_tokens(root: &SyntaxNode) -> impl Iterator<Item = SyntaxToken> {
    root.descendants_with_tokens()
        .filter_map(NodeOrToken::into_token)
        .filter(|t| t.kind() != K::WHITESPACE && !t.text().is_empty())
}

fn span_of(token: &SyntaxToken) -> ByteSpan {
    let r = token.text_range();
    ByteSpan::new(usize::from(r.start()), usize::from(r.end()))
}

/// A token outside a leaf node: a keyword or punctuation by the keyword table, a boolean, or a
/// name or a literal in an error region as it would read in a query that parses.
fn token_capture(token: &SyntaxToken, parent: K) -> Option<&'static str> {
    match token_name(token.kind(), token.text()) {
        ERROR_WORD | ERROR_QUOTED => Some("variable"),
        ERROR_TILDE_WORD => Some("function"),
        ERROR_STRING => Some("string"),
        ERROR_NUMBER => Some("number"),
        _ if parent == K::BOOLEAN => Some("boolean"),
        name => keyword_captures().get(name).copied(),
    }
}

/// The capture of each keyword and symbol of the highlight table, by text, built once: a
/// scan of the table per token was most of the highlight pass (ADR 0014 §2). The table's
/// first row for a text wins, as the scan's did.
fn keyword_captures() -> &'static HashMap<&'static str, &'static str> {
    static CAPTURES: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    CAPTURES.get_or_init(|| {
        let mut captures = HashMap::new();
        for (token, capture) in
            opentide_highlight::keywords(opentide_core::LanguageId::Eql).unwrap_or_default()
        {
            captures.entry(*token).or_insert(capture.name());
        }
        captures
    })
}

/// A leaf node, by its kind and its place in its parent.
fn leaf_capture(leaf: &SyntaxNode) -> Option<&'static str> {
    let kind = leaf.kind();
    let parent = leaf.parent().map(|p| p.kind());
    let first_named = leaf
        .parent()
        .and_then(|p| p.first_child())
        .is_some_and(|first| &first == leaf);
    // The grammar's fields that change a leaf's capture, by its place in its parent.
    let relation = parent == Some(K::RELATIONSHIP) && kind != K::SUBQUERY;
    let pipe_name = parent == Some(K::PIPE_STAGE) && first_named;
    let option_key = parent == Some(K::TERM_OPTION) && kind != K::NUMBER;
    let time_unit = parent == Some(K::TIME_UNIT) && kind != K::NUMBER;
    let call_name = parent == Some(K::FUNCTION_CALL) && first_named;
    Some(match kind {
        K::IDENTIFIER if relation => "error",
        K::IDENTIFIER if pipe_name || option_key => "keyword",
        K::IDENTIFIER if time_unit => "constant",
        K::IDENTIFIER | K::STRING if parent == Some(K::EVENT_CATEGORY) => "type",
        K::ANY => "type",
        K::IDENTIFIER | K::CASE_INSENSITIVE_NAME if call_name => "function",
        K::IDENTIFIER | K::QUOTED_IDENTIFIER if parent == Some(K::FIELD) => "property",
        K::INDEX | K::NUMBER => "number",
        K::OPTIONAL_MARKER | K::MISSING_EVENT_OPEN => "operator",
        K::IDENTIFIER | K::QUOTED_IDENTIFIER => "variable",
        K::STRING => "string",
        K::NULL => "constant",
        _ => return None,
    })
}

/// `EqlParser` scans the tokens before parsing: `(` and `)` move a depth counter, and a run of
/// prefix-capable `not`, `-`, `+` tokens adds to it; any other visible token ends the run.
/// Whitespace and comments do not. Returns the token where `depth + run` first exceeds the
/// limit.
///
/// `root` is the tree of `source`. A cheap bound comes first (ADR 0014 §4): `depth + run`
/// counts `(`, `not`, `-` and `+` tokens (`not` is a keyword only in lower case, as
/// `parser::keywords` reads it), and each holds one of the bytes `(`, `n`, `-` or `+`, so a source with no more of those bytes than the limit cannot exceed it.
pub(crate) fn expression_depth_exceeded(root: &SyntaxNode, source: &str) -> Option<ByteSpan> {
    let candidates = source
        .bytes()
        .filter(|b| matches!(b, b'(' | b'n' | b'-' | b'+'))
        .count();
    if i64::try_from(candidates).is_ok_and(|n| n <= lexical::MAX_EXPRESSION_DEPTH) {
        return None;
    }
    depth_walk(root)
}

thread_local! {
    /// The depth walks on this thread: [`depth_walks`].
    #[cfg(test)]
    static DEPTH_WALKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many times this thread walked a tree's tokens for the depth check (ADR 0014 §7).
#[cfg(test)]
pub(crate) fn depth_walks() -> usize {
    DEPTH_WALKS.get()
}

/// The token scan itself, over every visible token.
fn depth_walk(root: &SyntaxNode) -> Option<ByteSpan> {
    #[cfg(test)]
    DEPTH_WALKS.set(DEPTH_WALKS.get() + 1);
    let mut depth: i64 = 0;
    let mut chain: i64 = 0;
    for token in visible_tokens(root) {
        // A leaf node is one token to the scan, whatever its kind.
        let in_leaf = token.parent().is_some_and(|p| is_leaf(p.kind()));
        match token.kind() {
            K::L_PAREN if !in_leaf => depth += 1,
            K::R_PAREN if !in_leaf => depth -= 1,
            K::NOT_KW | K::MINUS | K::PLUS if !in_leaf => chain += 1,
            K::LINE_COMMENT | K::BLOCK_COMMENT => {}
            _ => chain = 0,
        }
        if depth + chain > lexical::MAX_EXPRESSION_DEPTH {
            return Some(span_of(&token));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Texts with every mix of nesting and prefix runs around the limit, and queries like the
    /// corpus's.
    fn texts() -> Vec<String> {
        let limit = usize::try_from(lexical::MAX_EXPRESSION_DEPTH).unwrap_or(250);
        let mut out = Vec::new();
        for n in [limit - 1, limit, limit + 1] {
            out.push(format!(
                "process where {}a == 1{}",
                "(".repeat(n),
                ")".repeat(n)
            ));
            out.push(format!("process where {}a", "not ".repeat(n)));
            out.push(format!("process where {}1 == 1", "-".repeat(n)));
            out.push(format!("process where {}+1 == 1", "+-".repeat(n / 2)));
            out.push(format!(
                "process where {}(a){}",
                "not (".repeat(n / 2),
                ")".repeat(n / 2)
            ));
            out.push(format!("process where a == \"{}\"", "(".repeat(n + 5)));
            out.push(format!("process where /* {} */ a", "(".repeat(n + 5)));
            out.push(format!("process where {}a", "NOT ".repeat(n)));
        }
        // Queries like the corpus's, written here: an engine crate reads no
        // file, its tests in `src/` included (`check-io-free.sh`).
        out.extend(
            [
            r#"sequence with maxspan=5w [a where true] [b where true]"#,
            r#"process where process.name in ()"#,
            r#"process where process.pid =="#,
            r#"process where ?process.parent.name == null and `odd field` != "x""#,
            r#"process where /* unterminated true"#,
            r#"sample by host.id [process where true] [file where true]"#,
            r#"sequence [process where true] ![file where true] [network where true] | head 1"#,
            r#"process where a == 0x10"#,
            r#"process where file.path == 'C:\Windows'"#,
            r#"process where not (a == 1 or -b == +2) and not c"#,
            r#"process where length(process.args) > -(3 + -4)"#,
            r#"network where destination.port in (22, 3389) and not cidrMatch(destination.ip, "10.0.0.0/8")"#,
            r#"process where process.name : "cmd*" // a comment ( ( ("#,
            r#"any where true | tail 5 | filter not x"#,
            ]
            .map(str::to_owned),
        );
        out
    }

    /// The bound cuts nothing the walk finds (ADR 0014 §4, §7).
    #[test]
    fn the_bound_cuts_nothing_the_walk_finds() {
        let (mut found, mut cut) = (0, 0);
        for source in texts() {
            let root = SyntaxNode::new_root(crate::parser::parse(&source).green);
            let walked = depth_walk(&root);
            assert_eq!(
                expression_depth_exceeded(&root, &source),
                walked,
                "{source:?}"
            );
            found += usize::from(walked.is_some());
            let before = depth_walks();
            expression_depth_exceeded(&root, &source);
            cut += usize::from(depth_walks() == before);
        }
        assert!(found >= 6 && cut >= 10, "{found} found, {cut} cut");
    }

    /// A short query is not walked: the walk ran on every analysis.
    #[test]
    fn a_short_query_is_not_walked() {
        let before = depth_walks();
        crate::analyze("process where not (a == 1 or b == -2)");
        assert_eq!(depth_walks() - before, 0);
    }

    /// The keyword index finds what a scan of the table finds, for each row's text.
    #[test]
    fn the_keyword_index_finds_what_a_scan_finds() {
        let table =
            opentide_highlight::keywords(opentide_core::LanguageId::Eql).unwrap_or_default();
        assert!(!table.is_empty());
        for (text, _) in table {
            let scanned = table.iter().find(|(t, _)| t == text).map(|(_, c)| c.name());
            assert_eq!(keyword_captures().get(text).copied(), scanned, "{text}");
        }
        assert_eq!(keyword_captures().get("no such keyword"), None);
    }
}
